'use strict';
/**
 * 登录流程：/vone/login/auth_param -> /vone/login/gid -> /vone/login/user_pswd
 *
 * 实测结论（见 docs/PROTOCOL.md）：
 *  - U / P 为明文（网关 ngvone 模式下不校验前端那层 RSA/Base64）
 *  - HASH 网关不校验内容，只要求 64 位十六进制
 *  - S_CODE 为 16 字节随机数的 Base64
 *  - 网关证书普遍过期或自签，故不校验证书链
 */
const https = require('https');
const crypto = require('crypto');

const UA = 'VONE-AUTH,WINDOWS,NULL,TOPCLINET,NULL';

class AuthError extends Error {
  constructor(message, code, raw) {
    super(message);
    this.code = code;
    this.raw = raw;
  }
}

const ERR_TEXT = {
  '-7': '请求格式错误（通常是 + 号未转义）',
  '-40018': '验证码错误',
  '-40077': '账号已在别处登录',
  '-40081': '账号或密码错误',
  '-40050': '账号被锁定',
};

/**
 * 解析网关返回的“伪 JSON”：键名不带引号，值可能是字符串。
 * 直接 JSON.parse 会失败，这里做一次键名加引号后再解析。
 */
function looseParse(text) {
  const s = text.indexOf('{');
  const e = text.lastIndexOf('}');
  if (s < 0 || e < 0) return null;
  const body = text.slice(s, e + 1);
  try { return JSON.parse(body); } catch { /* 继续尝试 */ }
  try {
    return JSON.parse(
      body
        .replace(/([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:/g, '$1"$2":')
        .replace(/,\s*([}\]])/g, '$1'),
    );
  } catch { return null; }
}

class AuthClient {
  constructor({ host, port, user, pass, timeout = 25000 }) {
    this.host = host;
    this.port = Number(port) || 443;
    this.user = user;
    this.pass = pass;
    this.timeout = timeout;
    this.cookie = '';
  }

  request(pathname, { method = 'GET', body = '', headers = {} } = {}) {
    return new Promise((resolve, reject) => {
      const h = {
        Host: this.host,
        'User-Agent': UA,
        Connection: 'keep-alive',
        ...headers,
      };
      if (this.cookie) h.Cookie = this.cookie;
      if (body) h['Content-Length'] = Buffer.byteLength(body);

      const req = https.request({
        host: this.host,
        port: this.port,
        path: pathname,
        method,
        headers: h,
        rejectUnauthorized: false,
        timeout: this.timeout,
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          const setCookie = [].concat(res.headers['set-cookie'] || []).map((s) => s.split(';')[0]);
          if (setCookie.length) {
            const merged = new Set(this.cookie ? this.cookie.split('; ') : []);
            setCookie.forEach((c) => merged.add(c));
            this.cookie = Array.from(merged).join('; ');
          }
          resolve({ status: res.statusCode, buf, text: buf.toString('utf8') });
        });
      });
      req.on('timeout', () => req.destroy(new Error('网关响应超时')));
      req.on('error', reject);
      if (body) req.write(body);
      req.end();
    });
  }

  /** 网关能力探测，同时种下第一个 cookie */
  async probe() {
    const r = await this.request('/vone/login/auth_param', {
      method: 'POST',
      headers: { Referer: `https://${this.host}/` },
    });
    return looseParse(r.text) || {};
  }

  /** 取图形验证码，返回 PNG Buffer */
  async captcha() {
    const r = await this.request('/vone/login/gid', {
      headers: { Referer: `https://${this.host}/` },
    });
    if (r.status !== 200 || r.buf.length < 100) throw new AuthError('验证码获取失败', r.status);
    return r.buf;
  }

  /** 提交账号密码与验证码 */
  async submit(code) {
    // 关键：+ 必须转义，否则网关按 URL 解码会把 + 变成空格
    const enc = (v) => encodeURIComponent(v).replace(/%20/g, '+');
    const body = [
      `U=${enc(this.user)}`,
      `P=${enc(this.pass)}`,
      `Gid=${enc(code)}`,
      `HASH=${'0'.repeat(64)}`,
      `S_CODE=${encodeURIComponent(crypto.randomBytes(16).toString('base64'))}`,
    ].join('&');

    const r = await this.request('/vone/login/user_pswd', {
      method: 'POST',
      body,
      headers: {
        Referer: `https://${this.host}/vone/login/user_pswd/`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    const res = looseParse(r.text);
    if (!res || typeof res.Ret === 'undefined') {
      throw new AuthError(`登录响应无法解析（HTTP ${r.status}）`, r.status, r.text.slice(0, 300));
    }
    if (res.Ret !== 0) {
      const msg = ERR_TEXT[String(res.Ret)] || res.ErrMsg || `登录失败（Ret=${res.Ret}）`;
      throw new AuthError(msg, res.Ret, res);
    }
    return res;
  }

  /** 注销会话，释放“单点登录”占位 */
  async logout(sessionId) {
    const saved = this.cookie;
    this.cookie = `topafasfasfassession_id=${sessionId}`;
    try {
      const r = await this.request('/vone/login/logout', {
        method: 'POST',
        headers: { Referer: `https://${this.host}/` },
      });
      return looseParse(r.text) || {};
    } finally {
      this.cookie = saved;
    }
  }
}

/** 把网关返回的 5 段结构整理成引擎内部使用的配置 */
function normalizeLogin(res) {
  const up = res.user_param || {};
  const net = res.net_param || {};
  const routes = [];
  const rl = res.route_list || [];
  const arr = Array.isArray(rl) ? rl : Object.keys(rl).sort((a, b) => a - b).map((k) => rl[k]);
  for (const item of arr) {
    if (!item || !item.dest) continue;
    const prefix = maskToPrefix(item.mask);
    if (prefix === null) continue;
    if (item.dest === '0.0.0.0') continue;
    routes.push({ dest: item.dest, mask: item.mask, prefix });
  }

  // dns_info.dns_list 形如 "10.22.1.137 http://luban.yfb.sunline.cn:3000\r\n"
  const hosts = [];
  const dnsList = (res.dns_info && res.dns_info.dns_list) || '';
  for (const line of String(dnsList).split(/\r?\n/)) {
    const m = line.trim().match(/^(\d+\.\d+\.\d+\.\d+)\s+(?:https?:\/\/)?([A-Za-z0-9_.-]+)(?::\d+)?/);
    if (m) hosts.push({ ip: m[1], name: m[2] });
  }

  const acl = [];
  const al = res.acl_list || {};
  const aclArr = Array.isArray(al) ? al : Object.keys(al).sort((a, b) => a - b).map((k) => al[k]);
  for (const a of aclArr) {
    if (!a) continue;
    acl.push({
      protocol: a.protocol,
      sport: a.sport,
      dport: a.dport,
      dest: a.d_ip_v4 || a.d_ip_v6,
      mask: a.d_mask,
      action: a.action,
      week: a.week,
      start: a.start_tm,
      end: a.end_tm,
    });
  }

  return {
    sessionId: up.topafasfasfassession_id,
    userName: up.username,
    vip: net.vip_v4,
    vipMask: net.vip_mask,
    dns1: net.dns1_v4,
    dns2: net.dns2_v4,
    tunnelType: net.tunnel_type,
    spaKey: up.spa_key,
    alg: up.alg,
    routes,
    hosts,
    acl,
  };
}

function maskToPrefix(mask) {
  if (!mask) return null;
  const parts = String(mask).split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
  let bits = 0;
  for (const part of parts) {
    let n = part;
    while (n & 0x80) { bits += 1; n = (n << 1) & 0xff; }
  }
  return bits;
}

module.exports = { AuthClient, AuthError, normalizeLogin, looseParse, maskToPrefix };
