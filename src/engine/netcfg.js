'use strict';
/**
 * 系统网络配置：给虚拟网卡配 IP、注入路由、维护 hosts 覆盖、设置网卡 DNS。
 *
 * 全部改动都记录在 cleanup 清单里，断开时按逆序撤销；
 * hosts 修改前会先备份，避免出现“卸载后残留”的情况。
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, execSync } = require('child_process');

const HOSTS = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
const MARK_BEGIN = '# >>> topsap-client begin >>>';
const MARK_END = '# <<< topsap-client end <<<';

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, {
    encoding: null,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    ...opts,
  });
}

/**
 * Windows 命令行的输出是系统代码页（简体中文为 GBK），
 * 按 UTF-8 读会变成乱码，所以这里先试 UTF-8，出现替换字符再退回 GBK。
 */
function decodeOutput(buf) {
  if (typeof buf === 'string') return buf;
  if (!Buffer.isBuffer(buf)) return buf == null ? '' : String(buf);
  const asUtf8 = buf.toString('utf8');
  if (!asUtf8.includes('\uFFFD')) return asUtf8;
  try {
    return new TextDecoder('gbk').decode(buf);
  } catch {
    return asUtf8;
  }
}

function tryRun(cmd, args) {
  try {
    return { ok: true, out: decodeOutput(run(cmd, args)) };
  } catch (err) {
    const out = decodeOutput(err.stdout) + decodeOutput(err.stderr);
    return { ok: false, out, err };
  }
}

/** 通过 netsh 取接口索引 */
function ifIndexByName(alias) {
  // 优先用 PowerShell 取，输出结构稳定；netsh 的输出会随系统语言变化
  const ps = tryRun('powershell', [
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
    `(Get-NetAdapter -Name '${alias}' -ErrorAction SilentlyContinue | Select-Object -First 1).ifIndex`,
  ]);
  if (ps.ok) {
    const n = parseInt(String(ps.out).trim(), 10);
    if (Number.isInteger(n) && n > 0) return n;
  }

  const r = tryRun('netsh', ['interface', 'ipv4', 'show', 'interfaces']);
  if (!r.ok) return null;
  for (const line of r.out.split(/\r?\n/)) {
    if (!line.includes(alias)) continue;
    const m = line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+)$/);
    if (m) return Number(m[1]);
  }
  return null;
}

/** 读接口上现有的 IPv4 地址 */
function interfaceIpv4(ifIndex) {
  const r = tryRun('powershell', [
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
    `(Get-NetIPAddress -InterfaceIndex ${ifIndex} -AddressFamily IPv4 -ErrorAction SilentlyContinue | `
    + `Select-Object -ExpandProperty IPAddress) -join ','`,
  ]);
  if (!r.ok) return [];
  return String(r.out).trim().split(',').map((s) => s.trim()).filter(Boolean);
}

function maskToPrefixLen(mask) {
  const parts = String(mask).split('.').map(Number);
  let bits = 0;
  for (const p of parts) {
    let n = p;
    while (n & 0x80) { bits += 1; n = (n << 1) & 0xff; }
  }
  return bits;
}

/** 取默认网关（用于给网关地址本身加一条旁路路由，避免流量绕回隧道） */
function defaultGateway() {
  const r = tryRun('route', ['print', '-4']);
  if (!r.ok) return null;
  let inDefault = false;
  for (const raw of r.out.split(/\r?\n/)) {
    const line = raw.trim();
    if (/^0\.0\.0\.0\s+0\.0\.0\.0/.test(line)) {
      const parts = line.split(/\s+/);
      if (parts.length >= 4) return { gw: parts[2], iface: parts[3] };
    }
    if (/^Active Routes:/i.test(line)) inDefault = true;
  }
  return inDefault ? null : null;
}

function macToIpList(mask) {
  return mask;
}

class NetConfig {
  constructor(alias) {
    this.alias = alias;
    this.ifIndex = null;
    this.injected = [];
    this.hostsBackup = null;
    this.dnsSet = false;
  }

  /**
   * 配置网卡地址。
   * 刚创建出来的虚拟网卡需要一点时间才可配置，且 netsh 在部分系统上会对 Wintun 网卡
   * 「返回成功但实际没生效」。所以这里最多三轮：每轮先后尝试 netsh 与 PowerShell，
   * 每轮结束都回读校验，三轮都失败才报错。
   */
  async configureInterface(vip, mask) {
    const idx = ifIndexByName(this.alias);
    if (idx === null) throw new Error(`未找到虚拟网卡「${this.alias}」，驱动可能未就绪`);
    this.ifIndex = idx;

    tryRun('netsh', ['interface', 'set', 'interface', `name=${this.alias}`, 'admin=enable']);

    const prefixLen = maskToPrefixLen(mask);
    const attempt = [];
    let actual = [];

    for (let round = 1; round <= 3; round++) {
      if (round === 1 || round === 3) {
        const r = tryRun('netsh', ['interface', 'ipv4', 'set', 'address', `name=${this.alias}`, 'static', vip, mask]);
        attempt.push(`第${round}轮 netsh=${r.ok ? 'ok' : 'fail'}`);
      } else {
        const r = tryRun('powershell', [
          '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
          `Remove-NetIPAddress -InterfaceIndex ${idx} -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue; `
          + `New-NetIPAddress -InterfaceIndex ${idx} -IPAddress ${vip} -PrefixLength ${prefixLen} -ErrorAction SilentlyContinue`,
        ]);
        attempt.push(`第${round}轮 powershell=${r.ok ? 'ok' : 'fail'}`);
      }

      await new Promise((r) => setTimeout(r, 600));
      actual = interfaceIpv4(idx);
      if (actual.includes(vip)) break;
    }

    if (!actual.includes(vip)) {
      throw new Error(`设置网卡地址失败（当前：${actual.join(',') || '无'}；${attempt.join('，')}）`);
    }

    tryRun('netsh', ['interface', 'ipv4', 'set', 'subinterface', this.alias, 'mtu=1400', 'store=active']);
    return idx;
  }

  /** 给网关地址本身加旁路路由，确保隧道连接不会自己走进隧道 */
  bypassGateway(gatewayHost) {
    const gwIp = resolveIPv4(gatewayHost);
    if (!gwIp) return;
    const def = defaultGateway();
    if (!def) return;
    const r = tryRun('route', ['ADD', gwIp, 'MASK', '255.255.255.255', def.gw, 'METRIC', '1']);
    if (r.ok) this.injected.push({ kind: 'bypass', dest: gwIp });
  }

  /** 读当前活动路由表（排除持久路由段），返回 "dest|mask" 集合 */
  activeRoutes() {
    const r = tryRun('route', ['print', '-4']);
    const set = new Set();
    if (!r.ok) return set;
    const lines = r.out.split(/\r?\n/);
    const cut = lines.findIndex((l) => /Persistent Routes|永久路由/i.test(l));
    const end = cut > 0 ? cut : lines.length;
    for (let i = 0; i < end; i++) {
      const m = lines[i].trim().match(/^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\d+/);
      if (m) set.add(`${m[1]}|${m[2]}`);
    }
    return set;
  }

  hasRoute(dest, mask) {
    return this.activeRoutes().has(`${dest}|${mask}`);
  }

  /**
   * 注入内网路由。
   * route.exe 在某些网卡上会接受参数但不落地，所以每条都回读校验，
   * 失败则改用另一套接口再试一次；返回真正生效的条数。
   */
  addRoutes(routes) {
    if (this.ifIndex === null) throw new Error('接口尚未初始化');
    const idx = this.ifIndex;
    let ok = 0;

    for (const rt of routes) {
      if (this.hasRoute(rt.dest, rt.mask)) {
        this.injected.push({ kind: 'route', dest: rt.dest, mask: rt.mask, preexisting: true });
        ok += 1;
        continue;
      }

      tryRun('route', ['ADD', rt.dest, 'MASK', rt.mask, '0.0.0.0', 'IF', String(idx), 'METRIC', '1']);
      if (!this.hasRoute(rt.dest, rt.mask)) {
        const prefix = `${rt.dest}/${maskToPrefixLen(rt.mask)}`;
        tryRun('powershell', [
          '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
          `New-NetRoute -DestinationPrefix ${prefix} -InterfaceIndex ${idx} -NextHop 0.0.0.0 `
          + `-RouteMetric 1 -ErrorAction SilentlyContinue`,
        ]);
      }

      if (this.hasRoute(rt.dest, rt.mask)) {
        this.injected.push({ kind: 'route', dest: rt.dest, mask: rt.mask });
        ok += 1;
      }
    }
    return ok;
  }

  /** 把网关下发的 dns_list 写成 hosts 覆盖段 */
  applyHosts(entries) {
    if (!entries || !entries.length) return 0;
    const content = fs.readFileSync(HOSTS, 'utf8');
    this.hostsBackup = content;

    const body = entries.map((e) => `${e.ip.padEnd(16)} ${e.name}`).join('\r\n');
    const block = `${MARK_BEGIN}\r\n${body}\r\n${MARK_END}`;
    const cleaned = stripBlock(content);
    const next = cleaned.trimEnd() + '\r\n\r\n' + block + '\r\n';
    fs.writeFileSync(HOSTS, next, 'utf8');
    tryRun('ipconfig', ['/flushdns']);
    return entries.length;
  }

  /** 设置网卡 DNS */
  setDns(dns1) {
    if (!dns1 || dns1 === '0.0.0.0') return false;
    const r = tryRun('netsh', ['interface', 'ipv4', 'set', 'dnsservers', `name=${this.alias}`, 'static', dns1, 'primary']);
    this.dnsSet = r.ok;
    return r.ok;
  }

  /** 撤销全部改动 */
  cleanup() {
    for (const item of this.injected.slice().reverse()) {
      if (item.kind === 'route' && !item.preexisting) {
        tryRun('route', ['DELETE', item.dest, 'MASK', item.mask, 'IF', String(this.ifIndex)]);
      } else if (item.kind === 'bypass') {
        tryRun('route', ['DELETE', item.dest, 'MASK', '255.255.255.255']);
      }
    }
    this.injected = [];

    if (this.hostsBackup !== null) {
      try {
        fs.writeFileSync(HOSTS, stripBlock(fs.readFileSync(HOSTS, 'utf8')), 'utf8');
        tryRun('ipconfig', ['/flushdns']);
      } catch { /* 忽略 */ }
      this.hostsBackup = null;
    }
  }
}

function stripBlock(text) {
  const i = text.indexOf(MARK_BEGIN);
  const j = text.indexOf(MARK_END);
  if (i < 0 || j < 0) return text;
  return (text.slice(0, i) + text.slice(j + MARK_END.length)).replace(/\r?\n{3,}/g, '\r\n\r\n');
}

/** 主机名转 IPv4；已经是 IP 就直接返回 */
function resolveIPv4(host) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return host;
  try {
    const out = execSync(`nslookup ${host}`, { encoding: 'utf8', timeout: 5000, windowsHide: true });
    const m = out.match(/Address:\s+(\d+\.\d+\.\d+\.\d+)/g);
    if (m && m.length) {
      const last = m[m.length - 1].match(/(\d+\.\d+\.\d+\.\d+)/);
      if (last) return last[1];
    }
  } catch { /* 忽略 */ }
  return null;
}

/** 检查是否管理员 */
function isElevated() {
  try {
    execFileSync('net', ['session'], { stdio: 'ignore', windowsHide: true });
    return true;
  } catch {
    return false;
  }
}

module.exports = {
  NetConfig, isElevated, ifIndexByName, interfaceIpv4, defaultGateway,
  stripBlock, maskToPrefixLen, decodeOutput, HOSTS,
};
