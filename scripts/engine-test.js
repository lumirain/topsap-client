'use strict';
/**
 * 引擎自测：不启动界面，直接跑「登录 → （可选）连接」这条链路。
 * 用于在没有 Electron/管理员权限的环境里验证协议与字段映射。
 *
 *   node scripts/engine-test.js <网关> <端口> <账号> <密码> [--connect]
 *
 * 验证码会保存为 captcha.png，看清后写入 .code.txt。
 * 加 --connect 时才会走建网卡/建隧道（需要管理员权限）。
 */
const fs = require('fs');
const path = require('path');
const { Engine } = require('../src/engine/engine');

const [, , gateway, port, user, password, ...rest] = process.argv;
const doConnect = rest.includes('--connect');
const ROOT = path.join(__dirname, '..');
const CODE = path.join(ROOT, '.code.txt');
const CAPTCHA = path.join(ROOT, 'captcha.png');

if (!gateway || !user || !password) {
  console.error('用法: node scripts/engine-test.js <网关> <端口> <账号> <密码> [--connect]');
  process.exit(2);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitCode() {
  if (fs.existsSync(CODE)) fs.unlinkSync(CODE);
  for (let i = 0; i < 400; i++) {
    if (fs.existsSync(CODE)) {
      const c = fs.readFileSync(CODE, 'utf8').trim();
      if (c) return c;
    }
    await sleep(300);
  }
  throw new Error('验证码输入超时');
}

const engine = new Engine({ appRoot: ROOT });
engine.on('log', (m) => console.log(m));
engine.on('state', (s) => console.log(`[状态] ${s.label}${s.detail ? ' — ' + s.detail : ''}`));
engine.on('error', (e) => console.log('[错误] ' + e.message));
engine.on('captcha', async ({ png }) => {
  fs.writeFileSync(CAPTCHA, png);
  console.log('验证码已保存: ' + CAPTCHA);
  try {
    const code = await waitCode();
    engine.submitCaptcha(code);
  } catch (e) {
    console.log('[错误] ' + e.message);
  }
});

(async () => {
  try {
    // 注意：这里传的是界面字段名，用来验证映射是否一致
    const s = await engine.login({ gateway, port: Number(port) || 443, user, password });
    console.log('\n===== 登录结果 =====');
    console.log('会话 ID   :', s.sessionId);
    console.log('虚拟 IP   :', `${s.vip}/${s.vipMask}`);
    console.log('DNS       :', s.dns1, s.dns2);
    console.log('路由      :', s.routes.map((r) => `${r.dest}/${r.prefix}`).join(', ') || '（无）');
    console.log('内网主机  :', s.hosts.map((h) => `${h.name}→${h.ip}`).join(', ') || '（无）');
    console.log('ACL 条数  :', s.acl.length);

    if (doConnect) {
      console.log('\n===== 建立连接 =====');
      await engine.connect();
      console.log('已连接，等待 8 秒观察统计…');
      await sleep(8000);
      engine.emitStats();
    }

    console.log('\n===== 收尾 =====');
    await engine.disconnect();
    console.log('已完成');
    process.exit(0);
  } catch (err) {
    console.error('\n失败：' + err.message);
    try { await engine.disconnect({ silent: true }); } catch { /* 忽略 */ }
    process.exit(1);
  }
})();
