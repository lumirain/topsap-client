'use strict';

const $ = (id) => document.getElementById(id);
const MAX_LOG_LINES = 500;

const el = {
  statusDot: $('statusDot'),
  statusText: $('statusText'),
  appVersion: $('appVersion'),
  elevHint: $('elevHint'),
  gateway: $('gateway'),
  port: $('port'),
  user: $('user'),
  password: $('password'),
  remember: $('remember'),
  btnConnect: $('btnConnect'),
  btnDisconnect: $('btnDisconnect'),
  captchaCard: $('captchaCard'),
  captchaImg: $('captchaImg'),
  captchaCode: $('captchaCode'),
  btnCaptcha: $('btnCaptcha'),
  statusCard: $('statusCard'),
  stateDetail: $('stateDetail'),
  stVip: $('stVip'),
  stRoutes: $('stRoutes'),
  stTime: $('stTime'),
  stUp: $('stUp'),
  stDown: $('stDown'),
  stPkts: $('stPkts'),
  log: $('log'),
  btnClearLog: $('btnClearLog'),
};

let connected = false;
let logging = false;

function appendLog(line) {
  const lines = el.log.textContent ? el.log.textContent.split('\n') : [];
  lines.push(line);
  if (lines.length > MAX_LOG_LINES) lines.splice(0, lines.length - MAX_LOG_LINES);
  el.log.textContent = lines.join('\n');
  el.log.scrollTop = el.log.scrollHeight;
}

function fmtBytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function fmtDuration(sec) {
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return [h, m, s].map((n) => String(n).padStart(2, '0')).join(':');
}

function setStatus(state, label, detail) {
  el.statusText.textContent = label;
  el.statusDot.className = 'dot ' + (
    state === 'connected' ? 'on' : (state === 'idle' ? '' : 'busy')
  );
  el.stateDetail.textContent = detail || '';
}

function setBusy(busy) {
  logging = busy;
  el.btnConnect.disabled = busy || connected;
  el.btnConnect.textContent = busy ? '处理中…' : '连接';
}

async function refreshBusy() {
  el.btnConnect.disabled = logging || connected;
  el.btnDisconnect.disabled = !connected && !logging;
}

// ---------- 事件绑定 ----------

el.btnConnect.addEventListener('click', async () => {
  const form = {
    gateway: el.gateway.value.trim(),
    port: Number(el.port.value) || 443,
    user: el.user.value.trim(),
    password: el.password.value,
    remember: el.remember.checked,
  };
  if (!form.gateway) return appendLog('请填写网关地址');
  if (!form.user) return appendLog('请填写账号');

  setBusy(true);
  el.statusCard.classList.remove('hidden');
  const r = await window.api.login(form);
  if (!r.ok) {
    setBusy(false);
    refreshBusy();
    appendLog('登录失败：' + r.error);
    el.captchaCard.classList.add('hidden');
    return;
  }
  el.captchaCard.classList.add('hidden');
  el.stVip.textContent = r.session.vip || '—';
  el.stRoutes.textContent = `${r.session.routes} 条`;
  appendLog(`登录成功，正在建立隧道…`);

  const c = await window.api.connect();
  setBusy(false);
  if (!c.ok) {
    appendLog('连接失败：' + c.error);
    refreshBusy();
    return;
  }
  connected = true;
  refreshBusy();
});

el.btnDisconnect.addEventListener('click', async () => {
  setBusy(true);
  const r = await window.api.disconnect();
  setBusy(false);
  connected = false;
  setStatus('idle', '未连接', '');
  refreshBusy();
  if (!r.ok) appendLog('断开时出错：' + r.error);
});

el.btnCaptcha.addEventListener('click', () => {
  const code = el.captchaCode.value.trim();
  if (!code) return el.captchaCode.focus();
  window.api.captcha(code);
  el.captchaCard.classList.add('hidden');
  el.captchaCode.value = '';
});

el.captchaCode.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') el.btnCaptcha.click();
});

el.btnClearLog.addEventListener('click', () => { el.log.textContent = ''; });

$('btnSelftest').addEventListener('click', async () => {
  const btn = $('btnSelftest');
  btn.disabled = true;
  btn.textContent = '自检中…';
  appendLog('开始网卡自检：临时创建虚拟网卡并用回环 ICMP 验证收发');
  const r = await window.api.selftest();
  btn.disabled = false;
  btn.textContent = '网卡自检';
  appendLog(r.ok ? '网卡自检通过：数据面收发正常' : '网卡自检未全部通过，详见上方输出');
});

// ---------- 主进程事件 ----------

window.api.on('engine:state', (s) => {
  setStatus(s.state, s.label, s.detail);
  if (s.state === 'connected') { connected = true; refreshBusy(); }
  if (s.state === 'idle') { connected = false; refreshBusy(); }
});

window.api.on('engine:log', (line) => appendLog(line));

window.api.on('engine:captcha', (c) => {
  el.captchaImg.src = 'data:image/png;base64,' + c.png;
  el.captchaCard.classList.remove('hidden');
  el.captchaCode.value = '';
  el.captchaCode.focus();
});

window.api.on('engine:stats', (s) => {
  el.stVip.textContent = s.vip || '—';
  el.stRoutes.textContent = `${s.routes} 条`;
  el.stTime.textContent = fmtDuration(s.duration);
  el.stUp.textContent = fmtBytes(s.up);
  el.stDown.textContent = fmtBytes(s.down);
  el.stPkts.textContent = `${s.packetsIn} / ${s.packetsOut}`;
});

window.api.on('engine:error', (msg) => {
  appendLog('错误：' + msg);
});

// ---------- 启动 ----------

(async () => {
  const info = await window.api.info();
  el.appVersion.textContent = `v${info.version} · ${info.arch}`;
  if (!info.elevated) {
    el.elevHint.textContent = '未以管理员身份运行，无法创建虚拟网卡';
    el.elevHint.classList.add('warn');
  }

  const s = await window.api.loadSettings();
  el.gateway.value = s.gateway || '';
  el.port.value = s.port || 443;
  el.user.value = s.user || '';
  el.password.value = s.password || '';
  el.remember.checked = !!s.remember;

  refreshBusy();
  appendLog('客户端已就绪');
})();
