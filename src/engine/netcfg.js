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
    encoding: 'utf8',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    ...opts,
  });
}

function tryRun(cmd, args) {
  try {
    return { ok: true, out: run(cmd, args) };
  } catch (err) {
    return { ok: false, out: (err.stdout || '') + (err.stderr || ''), err };
  }
}

/** 通过 netsh 取接口索引 */
function ifIndexByName(alias) {
  const r = tryRun('netsh', ['interface', 'ipv4', 'show', 'interfaces']);
  if (!r.ok) return null;
  for (const line of r.out.split(/\r?\n/)) {
    if (!line.includes(alias)) continue;
    const m = line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+)$/);
    if (m) return Number(m[1]);
  }
  return null;
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

  /** 配置网卡地址与 MTU */
  configureInterface(vip, mask) {
    const idx = ifIndexByName(this.alias);
    if (idx === null) throw new Error(`未找到虚拟网卡「${this.alias}」，驱动可能未就绪`);
    this.ifIndex = idx;

    const r = tryRun('netsh', ['interface', 'ipv4', 'set', 'address', `name=${this.alias}`, 'static', vip, mask]);
    if (!r.ok) throw new Error(`设置虚拟网卡地址失败：${r.out.trim()}`);

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

  /** 注入内网路由 */
  addRoutes(routes) {
    if (this.ifIndex === null) throw new Error('接口尚未初始化');
    for (const rt of routes) {
      const r = tryRun('route', [
        'ADD', rt.dest, 'MASK', rt.mask, '0.0.0.0',
        'IF', String(this.ifIndex), 'METRIC', '1',
      ]);
      if (r.ok) {
        this.injected.push({ kind: 'route', dest: rt.dest, mask: rt.mask });
      }
    }
    return this.injected.filter((i) => i.kind === 'route').length;
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
      if (item.kind === 'route') {
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

module.exports = { NetConfig, isElevated, ifIndexByName, defaultGateway, stripBlock, HOSTS };
