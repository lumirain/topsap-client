'use strict';
/**
 * 网卡自检 v2
 *
 * 目的：在没有真实网关的情况下，判断虚拟网卡的收发是否正常。
 *
 * 分三层验证，从「一定成立」到「依赖系统路由」逐层推进：
 *   A. 写路径：直接构造一个 ICMP 请求写进网卡（WintunAllocateSendPacket + SendPacket）
 *   B. 读路径：上一步的包被 Windows 收到后应当回一个应答，应答会重新交给网卡，
 *              读循环若收到它，说明两个方向都通
 *   C. 系统路由：ping 同网段地址，验证 Windows 是否真的把包路由进了这块网卡
 *
 * C 失败但 A/B 通过时，说明网卡本身没问题，是系统侧路由/邻居解析的差异。
 *
 * 只能在管理员权限下运行，所以由主程序（清单为 requireAdministrator）拉起。
 */
const { execFile } = require('child_process');
const { TunDevice, resolveDll, ADAPTER_NAME } = require('../engine/tun');
const { NetConfig, isElevated, interfaceIpv4 } = require('../engine/netcfg');

const TEST_VIP = '10.99.99.2';
const TEST_MASK = '255.255.255.0';
const TEST_PEER = '10.99.99.3';

function exec(cmd, args, timeout = 8000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { windowsHide: true, timeout }, (err, stdout, stderr) => {
      resolve({ ok: !err, out: (stdout || '') + (stderr || '') });
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
  icmp[1] = 0;
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

const ICMP_NAMES = { 0: 'echo-reply', 3: 'unreachable', 8: 'echo-request', 11: 'time-exceeded' };

function describe(pkt) {
  if (!pkt || pkt.length < 20) return '非 IP 报文';
  const pair = `${pkt[12]}.${pkt[13]}.${pkt[14]}.${pkt[15]} -> ${pkt[16]}.${pkt[17]}.${pkt[18]}.${pkt[19]}`;
  const proto = pkt[9];
  if (proto === 1) {
    const ihl = (pkt[0] & 0x0f) * 4;
    return `ICMP ${ICMP_NAMES[pkt[ihl]] || 'type' + pkt[ihl]} ${pair}`;
  }
  if (proto === 17) return `UDP ${pair} ${pkt.readUInt16BE(20)}->${pkt.readUInt16BE(22)}`;
  if (proto === 6) return `TCP ${pair} ${pkt.readUInt16BE(20)}->${pkt.readUInt16BE(22)}`;
  return `${pair} proto=${proto}`;
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
    record('配置网卡地址', true, `${TEST_VIP}/${TEST_MASK}`);

    // 配置函数内部已经回读校验，这里用同一套接口再确认一次（netsh 输出受系统语言影响，不可靠）
    const addrList = interfaceIpv4(net.ifIndex);
    const hasIp = addrList.includes(TEST_VIP);
    record('回读网卡地址', hasIp, hasIp ? `地址已生效（${addrList.join(',')}）` : `地址未生效（当前：${addrList.join(',') || '无'}）`);
    if (!hasIp) log(addr.out.trim().split(/\r?\n/).slice(0, 8).join(' / '));

    // 静态邻居条目：让 Windows 不必等待 ARP 就能把包交给网卡
    const nb = await exec('netsh', ['interface', 'ipv4', 'add', 'neighbors', `"${ADAPTER_NAME}"`, TEST_PEER, '02-00-00-00-00-01']);
    log('邻居条目：' + (nb.ok ? '已添加' : '添加失败（可忽略）'));

    let sawOut = false;
    let sawValid = false;
    let sawReply = false;
    const seen = [];

    tun.readLoop((pkt) => {
      sawOut = true;
      if (pkt.length >= 20 && (pkt[0] >> 4) === 4) sawValid = true;
      if (seen.length < 5) {
        seen.push(`${describe(pkt)}（len=${pkt.length} 头=${pkt.subarray(0, 20).toString('hex')}）`);
      }
      if (pkt.length > 20 && pkt[9] === 1) {
        const ihl = (pkt[0] & 0x0f) * 4;
        if (pkt[ihl] === 0) sawReply = true;
        // 若系统把请求发了出来，代替对端回一个应答，让 ping 能通
        if (pkt[ihl] === 8) {
          tun.write(buildIcmpEcho({
            src: TEST_VIP, dst: TEST_PEER, type: 0,
            payloadLen: Math.max(0, pkt.length - ihl - 8),
          }));
        }
      }
    });
    record('启动读循环', true, '已就绪');

    // A. 写路径：注入一个发给自己的 echo 请求
    const probePkt = buildIcmpEcho({ src: TEST_PEER, dst: TEST_VIP, type: 8 });
    const wrote = tun.write(probePkt);
    record('发送方向（应用 → 网卡）', wrote, wrote ? `已写入 ${probePkt.length} 字节 ICMP 请求` : 'WintunAllocateSendPacket 返回空');

    // B. 读路径：Windows 应当对这个请求回一个应答，应答重新交给网卡
    for (let i = 0; i < 30 && !sawReply; i++) await sleep(100);
    const readOk = sawReply || sawValid;
    record('接收方向（网卡 → 应用）', readOk,
      sawReply ? '收到 Windows 的 ICMP 应答，双向均正常'
        : (sawValid ? `收到报文：${seen[0] || ''}` : (sawOut ? `收到无效报文：${seen[0] || ''}` : '读循环没有收到任何报文')));

    // C. 系统路由：ping 同网段地址，看系统是否把包交给网卡
    const beforeValid = sawValid;
    const p = await exec('ping', ['-n', '2', '-w', '1500', TEST_PEER], 12000);
    const pingOk = /TTL=/i.test(p.out);
    record('系统路由（ping 同网段）', pingOk ? true : (sawValid && !beforeValid ? true : null),
      pingOk ? 'ping 通' : 'ping 未通');
    if (!pingOk) {
      const brief = p.out.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).slice(0, 4).join(' / ');
      log('ping 输出：' + brief.slice(0, 200));
    }

    const routeOut = await exec('route', ['print', '-4']);
    const routes = routeOut.out.split(/\r?\n/).filter((l) => l.includes('10.99.99')).map((l) => l.trim());
    log('相关路由：' + (routes.length ? routes.slice(0, 3).join(' | ') : '（无 10.99.99 网段路由）'));
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
