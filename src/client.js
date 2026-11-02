// 纯协议客户端 v2：支持会话复用，便于快速迭代隧道层
const https = require('https');
const tls = require('tls');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const HOST = process.env.TS_GW || '';
const PORT = parseInt(process.env.TS_PORT || '4431', 10);
const USER = process.env.TS_USER || '';
const PASS = process.env.TS_PASS || '';
const SESS_FILE = path.join(__dirname, 'session.json');
const CODEFILE = path.join(__dirname, 'code.txt');
const UA = 'VONE-AUTH,WINDOWS,NULL,TOPCLINET,NULL';

function http(pathname, { method = 'GET', body = '', headers = {}, cookie = '' } = {}) {
  return new Promise((resolve, reject) => {
    const h = { Host: HOST, 'User-Agent': UA, Connection: 'keep-alive', ...headers };
    if (cookie) h.Cookie = cookie;
    if (body) h['Content-Length'] = Buffer.byteLength(body);
    const req = https.request({ host: HOST, port: PORT, path: pathname, method, headers: h, rejectUnauthorized: false, timeout: 25000 }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        resolve({ status: res.statusCode, buf, text: buf.toString('utf8'), jar: [].concat(res.headers['set-cookie'] || []).map((s) => s.split(';')[0]).join('; ') });
      });
    });
    req.on('timeout', () => req.destroy(new Error('http timeout')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function looseParse(text) {
  const s = text.indexOf('{'), e = text.lastIndexOf('}');
  if (s < 0 || e < 0) return null;
  const body = text.slice(s, e + 1);
  try { return JSON.parse(body); } catch { /* fallthrough */ }
  try {
    return JSON.parse(body.replace(/([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:/g, '$1"$2":').replace(/,\s*([}\]])/g, '$1'));
  } catch { return null; }
}

async function doLogin() {
  console.log('[登录] auth_param ...');
  const ap = await http('/vone/login/auth_param', { method: 'POST', headers: { Referer: `https://${HOST}/` } });
  const cfg = looseParse(ap.text) || {};

  console.log('[登录] 取验证码 ...');
  const g = await http('/vone/login/gid', { cookie: ap.jar, headers: { Referer: `https://${HOST}/` } });
  fs.writeFileSync(path.join(__dirname, 'captcha-final.png'), g.buf);
  const jar = [ap.jar, g.jar].filter(Boolean).join('; ');

  if (fs.existsSync(CODEFILE)) fs.unlinkSync(CODEFILE);
  console.log('[登录] 等待验证码 -> ' + CODEFILE);
  let code = '';
  for (let i = 0; i < 300; i++) {
    if (fs.existsSync(CODEFILE)) {
      const c = fs.readFileSync(CODEFILE, 'utf8').trim();
      if (c) { code = c; break; }
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  if (!code) throw new Error('验证码超时');

  const scode = encodeURIComponent(crypto.randomBytes(16).toString('base64'));
  const hash = crypto.createHash('sha256').update(USER + PASS + code).digest('hex').toUpperCase();
  const body = `U=${encodeURIComponent(USER)}&P=${encodeURIComponent(PASS)}&Gid=${encodeURIComponent(code)}&HASH=${hash}&S_CODE=${scode}`;
  const r = await http('/vone/login/user_pswd', {
    method: 'POST', body, cookie: jar,
    headers: { Referer: `https://${HOST}/vone/login/user_pswd/`, 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  const res = looseParse(r.text) || {};
  if (res.Ret !== 0) throw new Error(`登录失败 Ret=${res.Ret} ${res.ErrMsg || ''}${res.Ret === -40077 ? '（账号已在别处登录）' : ''}`);
  const up = res.user_param || {};
  const net = res.net_param || {};
  const out = {
    sid: up.topafasfasfassession_id, vip: net.vip_v4, mask: net.vip_mask,
    dns1: net.dns1_v4, dns2: net.dns2_v4, spaKey: up.spa_key, alg: up.alg,
    gateway: HOST, port: PORT, at: Date.now(),
  };
  fs.writeFileSync(SESS_FILE, JSON.stringify(out, null, 2));
  console.log(`[登录] 成功 session=${out.sid} VIP=${out.vip}/${out.mask} DNS=${out.dns1}`);
  return out;
}

function loadSession() {
  if (fs.existsSync(SESS_FILE)) {
    const s = JSON.parse(fs.readFileSync(SESS_FILE, 'utf8'));
    if (Date.now() - s.at < 30 * 60 * 1000) return s;
  }
  return null;
}

function buildLoginFrame(session) {
  const f = Buffer.from(fs.readFileSync(path.join(__dirname, 'tpl-login.bin')));
  const off = f.indexOf(Buffer.from('470&bb70a290c038640'));
  if (off < 0) throw new Error('登录帧模板缺少占位');
  Buffer.alloc(f.length - off).copy(f, off);
  Buffer.from(session).copy(f, off);
  return f;
}

function frame(cmd, payload, seq) {
  const h = Buffer.alloc(16);
  h.writeUInt32BE(seq, 4);
  h.writeUInt32BE(payload.length, 8);
  h.writeUInt32BE(cmd, 12);
  return Buffer.concat([h, payload]);
}

function ipv4Checksum(buf) {
  let sum = 0;
  for (let i = 0; i < buf.length; i += 2) sum += buf.readUInt16BE(i);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

function buildDnsQuery(vip, dns, name) {
  const labels = name.split('.').flatMap((p) => [Buffer.from([p.length]), Buffer.from(p)]);
  const qname = Buffer.concat([...labels, Buffer.from([0])]);
  const dnsPayload = Buffer.concat([
    Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    qname, Buffer.from([0x00, 0x01, 0x00, 0x01]),
  ]);
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(41000 + Math.floor(Math.random() * 10000), 0);
  udp.writeUInt16BE(53, 2);
  udp.writeUInt16BE(8 + dnsPayload.length, 4);
  const payload = Buffer.concat([udp, dnsPayload]);
  const ip = Buffer.alloc(20);
  ip[0] = 0x45;
  ip.writeUInt16BE(20 + payload.length, 2);
  ip.writeUInt16BE(Math.floor(Math.random() * 65535), 4);
  ip[8] = 64; ip[9] = 17;
  vip.split('.').forEach((n, i) => (ip[12 + i] = +n));
  dns.split('.').forEach((n, i) => (ip[16 + i] = +n));
  ip.writeUInt16BE(ipv4Checksum(ip), 10);
  return Buffer.concat([ip, payload]);
}

function parseIp(buf) {
  if (buf.length < 20 || buf[0] !== 0x45) return null;
  const proto = buf[9];
  const off = (buf[0] & 0x0f) * 4;
  return {
    src: `${buf[12]}.${buf[13]}.${buf[14]}.${buf[15]}`,
    dst: `${buf[16]}.${buf[17]}.${buf[18]}.${buf[19]}`,
    proto,
    sport: proto === 17 || proto === 6 ? buf.readUInt16BE(off) : '',
    dport: proto === 17 || proto === 6 ? buf.readUInt16BE(off + 2) : '',
    len: buf.length,
  };
}

async function main() {
  if (!HOST) throw new Error('请设置环境变量 TS_GW（网关地址）');
  if (!USER || !PASS) throw new Error('请设置环境变量 TS_USER / TS_PASS');
  let s = loadSession();
  if (!s) s = await doLogin();
  else console.log(`[会话] 复用 ${s.sid} VIP=${s.vip}（${Math.round((Date.now() - s.at) / 1000)}s 前）`);

  console.log(`\n[隧道] 连接 ${s.gateway}:${s.port} ...`);
  const sock = tls.connect({ host: s.gateway, port: s.port, rejectUnauthorized: false }, () => {
    console.log('[隧道] TLS ' + sock.getProtocol());
    sock.write(Buffer.from('CONNECT 127.0.0.1:4430 HTTP/1.1\r\nhost:127.0.0.1\r\nUser-Agent: VONE-NA,WINDOWS,NULL,TOPCLINET,NULL\r\nProxy-Connection: Keep-Alive\r\n\r\n'));
    sock.write(buildLoginFrame(s.sid));
    console.log('[隧道] 登录帧已发');
  });

  let acc = Buffer.alloc(0);
  let seq = 8;
  let stage = 'waitLoginAck';
  let probes = 0;

  const sendProbe = (name) => {
    const pkt = buildDnsQuery(s.vip, s.dns1 || '10.22.50.5', name);
    // 帧头 +0x04 为报文类型：15 = IPv4 数据；+0x0C 固定为 1
    sock.write(frame(1, pkt, 15));
    console.log(`  -> DNS ${name} (${pkt.length}B) 类型=15`);
  };

  sock.on('data', (d) => {
    acc = Buffer.concat([acc, d]);
    while (acc.length >= 16) {
      const len = acc.readUInt32BE(8);
      const cmd = acc.readUInt32BE(12);
      if (acc.length < 16 + len) break;
      const p = acc.subarray(16, 16 + len);
      acc = acc.subarray(16 + len);
      const txt = p.toString('latin1').replace(/[^\x20-\x7e]/g, '.');
      const ip = parseIp(p);
      console.log(`  <- cmd=${cmd} len=${len}${ip ? ` IP ${ip.src}->${ip.dst} p${ip.proto} ${ip.sport}->${ip.dport}` : (/[a-zA-Z]{3}/.test(txt) ? ' ' + txt.slice(0, 150) : '')}`);

      if (stage === 'waitLoginAck' && cmd === 1) {
        stage = 'sentNotify';
        // 真实客户端登录后立刻发的 24 字节通知帧：seq=7 len=8 cmd=1 payload 8 个 0
        sock.write(frame(1, Buffer.alloc(8), 7));
        console.log('  -> 发送通知帧 seq=7 len=8');
        setTimeout(() => { if (probes === 0) { probes = 1; sendProbe('www.example.com'); } }, 1200);
      }
    }
  });

  sock.on('error', (e) => console.log('[隧道] 错误 ' + e.message));
  setTimeout(() => {
    console.log('\n[结束] 未发探针则重试一次');
    if (probes === 0) { probes = 1; sendProbe('example.org'); }
    setTimeout(() => process.exit(0), 6000);
  }, 9000);
}

main().catch((e) => { console.error('失败: ' + e.message); process.exit(1); });
