'use strict';
/**
 * 网卡自检
 *
 * 目的：在没有真实网关的情况下，判断这块虚拟网卡能不能真正承载 VPN 流量。
 *
 * 两项关键验证：
 *   A. 写路径：应用把 IP 包写进网卡（WintunAllocateSendPacket/SendPacket）
 *   B. 跨网段投递：让系统 ping 一个「不在网卡所在子网、但路由指向网卡」的地址。
 *      这正是真实 VPN 的形态（虚拟 IP 是 172.21.x.x，内网网段是 10.22.x.x），
 *      系统会把包直接交给网卡而不做 ARP 解析。读循环如果看到了这个包，
 *      说明真实场景下的下行通路是通的；我们再把回显应答写回去，ping 通即为闭环。
 *
 * 注意：不要用「ping 同网段地址」来测。同网段会触发 ARP，而对端不存在，
 * 必然超时，且不能说明任何问题。
 *
 * 只能在管理员权限下运行，由主程序（清单为 requireAdministrator）拉起。
 */
const { execFile } = require('child_process');
const { TunDevice, resolveDll, ADAPTER_NAME } = require('../engine/tun');
const { NetConfig, isElevated, interfaceIpv4, decodeOutput } = require('../engine/netcfg');

const TEST_VIP = '10.99.99.2';
const TEST_MASK = '255.255.255.0';
const TEST_REMOTE = '10.98.0.5';        // 刻意放在另一个网段
const TEST_ROUTE = { dest: '10.98.0.0', mask: '255.255.0.0' };

function exec(cmd, args, timeout = 10000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { windowsHide: true, timeout, encoding: null }, (err, stdout, stderr) => {
      resolve({ ok: !err, out: decodeOutput(stdout) + decodeOutput(stderr) });
    });
  });
}

function checksum(buf) {
  let sum = 0;
  for (let i = 0; i + 1 < buf.length; i += 2) sum += buf.readUInt16BE(i);
  if (buf.length % 2) sum += buf[buf.length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

function ipToBuf(ip, buf, off) {
  ip.split('.').forEach((n, i) => { buf[off + i] = Number(n); });
}

function buildIcmpEcho({ src, dst, type = 8, id = 0x1234, seq = 1, payloadLen = 16 }) {
  const payload = Buffer.alloc(payloadLen);
  for (let i = 0; i < payloadLen; i++) payload[i] = i;
  const icmp = Buffer.alloc(8 + payloadLen);
  icmp[0] = type;
  icmp.writeUInt16BE(id, 4);
  icmp.writeUInt16BE(seq, 6);
  payload.copy(icmp, 8);
  icmp.writeUInt16BE(checksum(icmp), 2);

  const ip = Buffer.alloc(20);
  ip[0] = 0x45;
  ip.writeUInt16BE(20 + icmp.length, 2);
  ip.writeUInt16BE(0x4321, 4);
  ip[8] = 64;
  ip[9] = 1;
  ipToBuf(src, ip, 12);
  ipToBuf(dst, ip, 16);
  ip.writeUInt16BE(checksum(ip), 10);
  return Buffer.concat([ip, icmp]);
}

/** 把收到的 ICMP 请求改写成应答（交换源/目的地址） */
function makeReply(pkt) {
  const ihl = (pkt[0] & 0x0f) * 4;
  if (pkt.length < ihl + 8 || pkt[9] !== 1 || pkt[ihl] !== 8) return null;
  const out = Buffer.from(pkt);
  out[ihl] = 0;
  out.writeUInt16BE(0, ihl + 2);
  out.writeUInt16BE(checksum(out.subarray(ihl)), ihl + 2);
  pkt.copy(out, 12, 16, 20);
  pkt.copy(out, 16, 12, 16);
  out[8] = 64;
  out.writeUInt16BE(0, 10);
  out.writeUInt16BE(checksum(out.subarray(0, ihl)), 10);
  return out;
}

const ICMP_NAMES = { 0: 'echo-reply', 3: 'unreachable', 8: 'echo-request', 11: 'time-exceeded' };

function describe(pkt) {
  if (!pkt || pkt.length < 20) return `非 IP 报文（${pkt ? pkt.length : 0} 字节）`;
  const version = pkt[0] >> 4;
  if (version === 6) {
    const nh = pkt[6];
    const name = nh === 58 ? 'ICMPv6' : (nh === 17 ? 'UDP' : (nh === 6 ? 'TCP' : `next=${nh}`));
    return `IPv6 ${name}（${pkt.length} 字节）`;
  }
  if (version !== 4) return `未知版本 ${version}（${pkt.length} 字节）`;

  const pair = `${pkt[12]}.${pkt[13]}.${pkt[14]}.${pkt[15]} → ${pkt[16]}.${pkt[17]}.${pkt[18]}.${pkt[19]}`;
  if (pkt[9] === 1) {
    const ihl = (pkt[0] & 0x0f) * 4;
    return `ICMP ${ICMP_NAMES[pkt[ihl]] || 'type' + pkt[ihl]} ${pair}`;
  }
  if (pkt[9] === 17) return `UDP ${pair} ${pkt.readUInt16BE(20)}→${pkt.readUInt16BE(22)}`;
  if (pkt[9] === 6) return `TCP ${pair} ${pkt.readUInt16BE(20)}→${pkt.readUInt16BE(22)}`;
  return `${pair} proto=${pkt[9]}`;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function run(log) {
  const steps = [];
  const record = (name, ok, detail) => {
    steps.push({ name, ok, detail });
    log(`[${ok === true ? 'OK  ' : (ok === null ? 'INFO' : 'FAIL')}] ${name}${detail ? ' — ' + detail : ''}`);
  };

  record('管理员权限', isElevated(), isElevated() ? '已提权' : '未提权，后续会失败');

  let tun = null;
  let net = null;
  try {
    const dll = resolveDll(process.resourcesPath && process.resourcesPath.includes('resources')
      ? process.resourcesPath
      : process.cwd());
    record('定位 wintun.dll', true, dll);

    tun = new TunDevice(dll).open();
    record('创建虚拟网卡与会话', true, ADAPTER_NAME);

    net = new NetConfig(ADAPTER_NAME);
    await net.configureInterface(TEST_VIP, TEST_MASK);
    const addrList = interfaceIpv4(net.ifIndex);
    const hasIp = addrList.includes(TEST_VIP);
    record('配置网卡地址', hasIp, hasIp ? `${TEST_VIP}/${TEST_MASK} 已生效` : `当前：${addrList.join(',') || '无'}`);

    const added = net.addRoutes([TEST_ROUTE]);
    record('注入测试路由', added === 1, added === 1 ? `${TEST_ROUTE.dest}/${TEST_ROUTE.mask} 已生效` : '路由未生效');

    let sawValid = false;
    let sawRequest = false;
    let sawReply = false;
    const seen = [];

    tun.readLoop((pkt) => {
      const ver = pkt.length >= 20 ? (pkt[0] >> 4) : 0;
      if (ver === 4 || ver === 6) sawValid = true;
      if (seen.length < 4) seen.push(`${describe(pkt)}（${pkt.length} 字节，头 ${pkt.subarray(0, 12).toString('hex')}）`);

      const reply = makeReply(pkt);
      if (reply) {
        sawRequest = true;
        tun.write(reply);
      } else if (pkt.length >= 20 && pkt[9] === 1 && pkt[(pkt[0] & 0x0f) * 4] === 0) {
        sawReply = true;
      }
    });
    record('启动读循环', true, '已就绪');

    // A. 写路径：往网卡里写一个包
    const probe = buildIcmpEcho({ src: TEST_REMOTE, dst: TEST_VIP, type: 8 });
    const wrote = tun.write(probe);
    record('发送方向（应用 → 网卡）', wrote, wrote ? `写入 ${probe.length} 字节` : 'WintunAllocateSendPacket 返回空');

    // B. 跨网段投递：这是真实 VPN 的形态
    const p = await exec('ping', ['-n', '2', '-w', '1200', TEST_REMOTE], 15000);
    const pingOk = /TTL=/i.test(p.out);
    record('系统路由（跨网段投递）', pingOk ? true : (sawRequest ? true : (sawValid ? null : false)),
      pingOk ? `ping ${TEST_REMOTE} 成功，系统已把包交给网卡且应答回注成功`
        : (sawRequest ? `已收到发往 ${TEST_REMOTE} 的请求，说明系统确实把包交给了网卡`
          : '没有看到任何发往该地址的报文'));

    if (!pingOk) {
      const brief = p.out.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).slice(0, 3).join(' / ');
      log('ping 输出：' + brief.slice(0, 160));
    }
    if (seen.length) log('收到报文：' + seen[0]);
    if (sawReply) log('（同时收到了 ICMP 回显应答）');
  } catch (err) {
    record('执行异常', false, err.message);
  } finally {
    if (tun) { try { tun.close(); } catch { /* 忽略 */ } }
    if (net) { try { net.cleanup(); } catch { /* 忽略 */ } }
  }

  const hardFail = steps.filter((s) => s.ok === false);
  log(`\n结果：${steps.filter((s) => s.ok === true).length}/${steps.length} 项通过`
    + (hardFail.length ? `，未通过：${hardFail.map((s) => s.name).join('、')}` : ''));
  return hardFail.length === 0;
}

module.exports = { run };
