'use strict';
/**
 * 网卡自检：不需要真实网关，用「自己回自己的 ICMP」验证整条数据面。
 *
 * 原理：
 *   1. 建虚拟网卡并配一个测试网段地址
 *   2. 让系统 ping 同网段内一个不存在的地址 —— 这个请求必然被写进虚拟网卡
 *   3. 读循环收到该 ICMP 请求后，改写成应答再写回网卡
 *   4. ping 如果能通，说明「读」和「写」两个方向都正常
 *
 * 只能在管理员权限下运行，所以由主程序（清单为 requireAdministrator）拉起。
 */
const { execFile } = require('child_process');
const { TunDevice, resolveDll, ADAPTER_NAME } = require('../engine/tun');
const { NetConfig, isElevated } = require('../engine/netcfg');

const TEST_VIP = '10.99.99.2';
const TEST_MASK = '255.255.255.0';
const TEST_PEER = '10.99.99.3';

function ping(host, timeoutMs = 4000) {
  return new Promise((resolve) => {
    execFile('ping', ['-n', '1', '-w', String(timeoutMs), host], { windowsHide: true }, (err, stdout) => {
      resolve({ ok: !err && /TTL=/i.test(stdout || ''), out: stdout || '' });
    });
  });
}

function icmpChecksum(buf) {
  let sum = 0;
  for (let i = 0; i + 1 < buf.length; i += 2) sum += buf.readUInt16BE(i);
  if (buf.length % 2) sum += buf[buf.length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

/** 把 ICMP echo request 改成 echo reply */
function toEchoReply(pkt) {
  const ihl = (pkt[0] & 0x0f) * 4;
  if (pkt[9] !== 1 || pkt[ihl] !== 8) return null;
  const out = Buffer.from(pkt);
  out[ihl] = 0; // type: reply
  out[ihl + 2] = 0;
  out[ihl + 3] = 0;
  const ck = icmpChecksum(out.subarray(ihl));
  out.writeUInt16BE(ck, ihl + 2);
  // 交换源/目的地址
  out.copyWithin(12, 16, 20);
  pkt.copy(out, 16, 12, 16);
  out[8] = 64;
  out[10] = 0;
  out[11] = 0;
  const ipck = icmpChecksum(out.subarray(0, ihl));
  out.writeUInt16BE(ipck, 10);
  return out;
}

async function run(log) {
  const steps = [];
  const record = (name, ok, detail) => {
    steps.push({ name, ok, detail });
    log(`[${ok ? 'OK ' : 'FAIL'}] ${name}${detail ? ' — ' + detail : ''}`);
  };

  record('管理员权限', isElevated(), isElevated() ? '已提权' : '未提权，后续步骤会失败');

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
    net.configureInterface(TEST_VIP, TEST_MASK);
    record('配置网卡地址', true, `${TEST_VIP}/${TEST_MASK}`);

    let sawRequest = false;
    let echoed = false;
    tun.readLoop((pkt) => {
      const reply = toEchoReply(pkt);
      if (!reply) return;
      sawRequest = true;
      if (tun.write(reply)) echoed = true;
    });
    record('启动读循环', true, '等待 ICMP 请求');

    const r = await ping(TEST_PEER);
    record('接收方向（网卡 → 应用）', sawRequest, sawRequest ? '收到 ICMP 请求' : '未收到任何报文');
    record('发送方向（应用 → 网卡）', echoed, echoed ? '已写回应答' : '未写出报文');
    record('端到端 ping', r.ok, r.ok ? 'ping 通' : '未通（若前两步为 FAIL，属于预期）');
  } catch (err) {
    record('执行异常', false, err.message);
  } finally {
    if (tun) { try { tun.close(); } catch { /* 忽略 */ } }
    if (net) { try { net.cleanup(); } catch { /* 忽略 */ } }
  }

  const passed = steps.filter((s) => s.ok).length;
  log(`\n结果：${passed}/${steps.length} 项通过`);
  return steps.every((s) => s.ok);
}

module.exports = { run };
