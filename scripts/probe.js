'use strict';
/**
 * 协议自检（不需要管理员权限、不创建虚拟网卡）
 *
 * 用途：验证登录与隧道层是否正常工作。会把验证码存到 captcha.png，
 * 等待同目录下出现 code.txt 后继续。连着跑通过说明协议栈是好的。
 *
 *   node scripts/probe.js vpn.example.com 443 user pass
 */
const fs = require('fs');
const path = require('path');
const { AuthClient, normalizeLogin } = require('../src/engine/auth');
const { Tunnel } = require('../src/engine/tunnel');

const HOST = process.argv[2] || process.env.TS_GW;
const PORT = Number(process.argv[3] || process.env.TS_PORT || 443);
const USER = process.argv[4] || process.env.TS_USER;
const PASS = process.argv[5] || process.env.TS_PASS;

const CODE_FILE = path.join(__dirname, '..', '.code.txt');
const CAPTCHA_FILE = path.join(__dirname, '..', 'captcha.png');

function buildDnsQuery(srcIp, dnsIp, name) {
  const labels = name.split('.').flatMap((p) => [Buffer.from([p.length]), Buffer.from(p)]);
  const qname = Buffer.concat([...labels, Buffer.from([0])]);
  const dns = Buffer.concat([
    Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    qname, Buffer.from([0x00, 0x01, 0x00, 0x01]),
  ]);
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(40000 + Math.floor(Math.random() * 20000), 0);
  udp.writeUInt16BE(53, 2);
  udp.writeUInt16BE(8 + dns.length, 4);
  const payload = Buffer.concat([udp, dns]);
  const ip = Buffer.alloc(20);
  ip[0] = 0x45;
  ip.writeUInt16BE(20 + payload.length, 2);
  ip.writeUInt16BE(Math.floor(Math.random() * 65535), 4);
  ip[8] = 64;
  ip[9] = 17;
  srcIp.split('.').forEach((n, i) => { ip[12 + i] = +n; });
  dnsIp.split('.').forEach((n, i) => { ip[16 + i] = +n; });
  let sum = 0;
  for (let i = 0; i < 20; i += 2) sum += ip.readUInt16BE(i);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  ip.writeUInt16BE((~sum) & 0xffff, 10);
  return Buffer.concat([ip, payload]);
}

async function waitCode() {
  if (fs.existsSync(CODE_FILE)) fs.unlinkSync(CODE_FILE);
  for (let i = 0; i < 400; i++) {
    if (fs.existsSync(CODE_FILE)) {
      const c = fs.readFileSync(CODE_FILE, 'utf8').trim();
      if (c) return c;
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error('验证码输入超时');
}

(async () => {
  if (!HOST || !USER || !PASS) {
    console.error('用法: node scripts/probe.js <网关> <端口> <账号> <密码>');
    process.exit(2);
  }

  const auth = new AuthClient({ host: HOST, port: PORT, user: USER, pass: PASS });
  await auth.probe();
  const png = await auth.captcha();
  fs.writeFileSync(CAPTCHA_FILE, png);
  console.log('验证码已保存: ' + CAPTCHA_FILE);
  const code = await waitCode();

  const raw = await auth.submit(code);
  const s = normalizeLogin(raw);
  s.gateway = HOST;
  s.port = PORT;
  console.log(`登录成功 session=${s.sessionId} vip=${s.vip} dns=${s.dns1}`);
  console.log(`路由 ${s.routes.length} 条: ${s.routes.map((r) => `${r.dest}/${r.prefix}`).join(', ')}`);
  console.log(`内网主机 ${s.hosts.length} 条: ${s.hosts.map((h) => h.name).join(', ')}`);

  const tunnel = new Tunnel(s);
  let replied = false;

  tunnel.on('log', (m) => console.log('[隧道] ' + m));
  tunnel.on('error', (e) => { console.error('[隧道] 错误 ' + e.message); process.exit(1); });
  tunnel.on('packet', (pkt) => {
    if (pkt.length > 20 && pkt[9] === 17) {
      replied = true;
      console.log(`收到隧道回包: ${pkt[12]}.${pkt[13]}.${pkt[14]}.${pkt[15]} -> ${pkt[16]}.${pkt[17]}.${pkt[18]}.${pkt[19]} UDP ${pkt.readUInt16BE(20)}->${pkt.readUInt16BE(22)} ${pkt.length} 字节`);
    }
  });
  tunnel.once('ready', () => {
    console.log('隧道握手完成');
    setTimeout(() => {
      const pkt = buildDnsQuery(s.vip, s.dns1, 'www.example.com');
      tunnel.sendPacket(pkt);
      console.log('已发出 DNS 探针 ' + pkt.length + ' 字节');
    }, 800);
  });

  tunnel.connect();

  setTimeout(async () => {
    console.log(replied ? '\n结果：数据面正常（收到隧道回包）' : '\n结果：未收到回包，数据面可能有问题');
    tunnel.destroy();
    try { await auth.logout(s.sessionId); } catch { /* 忽略 */ }
    process.exit(replied ? 0 : 1);
  }, 15000);
})().catch((e) => { console.error('失败: ' + e.message); process.exit(1); });
