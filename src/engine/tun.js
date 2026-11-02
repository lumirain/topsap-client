'use strict';
/**
 * TUN 层：通过 koffi 绑定 WireGuard 的 wintun.dll，创建三层虚拟网卡。
 *
 * 之所以选 Wintun：它是微软签名的驱动，wintun.dll 自带驱动文件，
 * CreateAdapter 时会自动安装，不需要单独发布 .sys 或走驱动安装流程。
 * 代价是必须管理员权限运行（这正是安装包以 requireAdministrator 发布的原因）。
 */
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

const ADAPTER_NAME = 'TopSAP';
const TUNNEL_TYPE = 'TopSAP';
const RING_CAPACITY = 0x400000; // 4 MB

// 固定的适配器 GUID，保证多次运行复用同一块虚拟网卡
const ADAPTER_GUID = {
  Data1: 0x7a4d1c62,
  Data2: 0x3b8f,
  Data3: 0x4e21,
  Data4: [0x9c, 0x5a, 0x11, 0x7e, 0x42, 0x88, 0x01, 0xd3],
};

let koffi = null;
let GUID = null;

function loadWintun(dllPath) {
  if (!koffi) {
    koffi = require('koffi');
    GUID = koffi.struct('GUID', {
      Data1: 'uint32',
      Data2: 'uint16',
      Data3: 'uint16',
      Data4: koffi.array('uint8_t', 8),
    });
  }
  if (!fs.existsSync(dllPath)) throw new Error(`找不到 wintun.dll：${dllPath}`);
  const lib = koffi.load(dllPath);
  // 注意：koffi 在声明函数签名时就会解析符号，任何一个不存在的导出都会让整段绑定失败，
  // 所以这里逐个绑定并给出明确的缺失项名称。
  const bind = (sig) => {
    try {
      return lib.func(sig);
    } catch (err) {
      const name = sig.split('(')[0].trim().split(/\s+/).pop();
      throw new Error(`wintun.dll 缺少导出函数 ${name}（${err.message}）`);
    }
  };

  // Wintun 的错误码走 Win32 GetLastError，wintun.dll 本身不导出 WintunGetLastError
  const k32 = koffi.load('kernel32.dll');
  const bindK32 = (sig) => {
    try { return k32.func(sig); } catch { return null; }
  };

  return {
    CreateAdapter: bind('void * WintunCreateAdapter(str16 Name, str16 TunnelType, GUID *RequestedGUID)'),
    OpenAdapter: bind('void * WintunOpenAdapter(str16 Name)'),
    CloseAdapter: bind('void WintunCloseAdapter(void *Adapter)'),
    StartSession: bind('void * WintunStartSession(void *Adapter, uint32 Capacity)'),
    EndSession: bind('void WintunEndSession(void *Session)'),
    GetReadWaitEvent: bind('void * WintunGetReadWaitEvent(void *Session)'),
    ReceivePacket: bind('void * WintunReceivePacket(void *Session, _Out_ uint32 *PacketSize)'),
    ReleaseReceivePacket: bind('void WintunReleaseReceivePacket(void *Session, void *Packet)'),
    AllocateSendPacket: bind('void * WintunAllocateSendPacket(void *Session, uint32 PacketSize)'),
    SendPacket: bind('void WintunSendPacket(void *Session, void *Packet)'),
    GetLastError: bindK32('uint32 GetLastError()') || (() => 0),
    // 必须显式引用 kernel32 的等待函数，否则读循环只能忙等
    WaitForSingleObject: bindK32('uint32 WaitForSingleObject(void *hHandle, uint32 dwMilliseconds)') || null,
  };
}

class TunDevice extends EventEmitter {
  constructor(dllPath) {
    super();
    this.dllPath = dllPath;
    this.api = null;
    this.adapter = null;
    this.session = null;
    this.waitEvent = null;
    this.running = false;
    this.packetsIn = 0;
    this.packetsOut = 0;
    this.droppedOut = 0;
  }

  /** 创建（或复用）虚拟网卡并开启会话 */
  open() {
    this.api = loadWintun(this.dllPath);

    let adapter = this.api.OpenAdapter(ADAPTER_NAME);
    if (!adapter) {
      adapter = this.api.CreateAdapter(ADAPTER_NAME, TUNNEL_TYPE, ADAPTER_GUID);
    }
    if (!adapter) {
      const err = this.api.GetLastError();
      throw new Error(wintunError(err, '创建虚拟网卡失败'));
    }
    this.adapter = adapter;

    const session = this.api.StartSession(adapter, RING_CAPACITY);
    if (!session) {
      const err = this.api.GetLastError();
      this.api.CloseAdapter(adapter);
      this.adapter = null;
      throw new Error(wintunError(err, '启动网卡会话失败'));
    }
    this.session = session;
    this.waitEvent = this.api.GetReadWaitEvent(session) || null;
    return this;
  }

  /** 读循环：把网卡上的 IP 包交给回调 */
  async readLoop(onPacket) {
    this.running = true;
    const { ReceivePacket, ReleaseReceivePacket, WaitForSingleObject } = this.api;
    const sizeHolder = [0];

    while (this.running && this.session) {
      try {
        if (this.waitEvent && WaitForSingleObject) {
          const w = WaitForSingleObject(this.waitEvent, 0);
          if (w !== 0) { await sleep(1); continue; }
        } else {
          await sleep(1);
        }
        for (;;) {
          sizeHolder[0] = 0;
          const ptr = ReceivePacket(this.session, sizeHolder);
          if (!ptr) break;
          const size = sizeHolder[0];
          if (size > 0) {
            const pkt = koffi.decode(ptr, koffi.array('uint8_t', size));
            ReleaseReceivePacket(this.session, ptr);
            this.packetsIn += 1;
            onPacket(Buffer.from(pkt.buffer ? pkt.buffer.slice(pkt.byteOffset, pkt.byteOffset + pkt.byteLength) : pkt));
          } else {
            ReleaseReceivePacket(this.session, ptr);
          }
        }
      } catch (err) {
        if (!this.running) break;
        this.emit('error', err);
        await sleep(20);
      }
    }
  }

  /** 把一个 IP 包写进网卡（即注入到系统网络栈） */
  write(packet) {
    if (!this.session) return false;
    const { AllocateSendPacket, SendPacket } = this.api;
    const ptr = AllocateSendPacket(this.session, packet.length);
    if (!ptr) {
      this.droppedOut += 1;
      return false;
    }
    koffi.encode(ptr, koffi.array('uint8_t', packet.length), packet);
    SendPacket(this.session, ptr);
    this.packetsOut += 1;
    return true;
  }

  close() {
    this.running = false;
    try {
      if (this.session) this.api.EndSession(this.session);
    } catch { /* 忽略 */ }
    try {
      if (this.adapter) this.api.CloseAdapter(this.adapter);
    } catch { /* 忽略 */ }
    this.session = null;
    this.adapter = null;
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function wintunError(code, prefix) {
  const map = {
    5: '拒绝访问（需要管理员权限）',
    87: '参数错误',
    1168: '找不到驱动',
    1077: '驱动尚未安装',
  };
  return `${prefix}：${map[code] || 'Win32 错误 ' + code}`;
}

/** 定位 wintun.dll：优先安装目录，其次源码目录 */
function resolveDll(appRoot) {
  const candidates = [
    path.join(appRoot, 'wintun.dll'),
    path.join(appRoot, 'assets', 'wintun', 'wintun.dll'),
    path.join(appRoot, '..', 'assets', 'wintun', 'wintun.dll'),
  ];
  for (const p of candidates) if (fs.existsSync(p)) return p;
  throw new Error('未找到 wintun.dll，请检查安装是否完整');
}

module.exports = { TunDevice, resolveDll, ADAPTER_NAME };
