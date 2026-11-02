'use strict';
const path = require('path');
const fs = require('fs');
const { app, BrowserWindow, ipcMain, dialog, safeStorage, shell } = require('electron');
const { Engine } = require('../engine/engine');
const { isElevated } = require('../engine/netcfg');

const isDev = !app.isPackaged;
const appRoot = isDev ? path.join(__dirname, '..', '..') : process.resourcesPath;

let win = null;
let engine = null;
let quitting = false;

function settingsPath() {
  return path.join(app.getPath('userData'), 'settings.json');
}

function loadSettings() {
  try {
    const raw = JSON.parse(fs.readFileSync(settingsPath(), 'utf8'));
    if (raw.password && raw.passwordEnc && safeStorage.isEncryptionAvailable()) {
      try {
        raw.password = safeStorage.decryptString(Buffer.from(raw.passwordEnc, 'base64'));
      } catch { raw.password = ''; }
    }
    delete raw.passwordEnc;
    return raw;
  } catch {
    return { gateway: '', port: 443, user: '', password: '', remember: false };
  }
}

function saveSettings(s) {
  const out = { ...s };
  out.password = '';
  if (s.remember && s.password && safeStorage.isEncryptionAvailable()) {
    out.passwordEnc = safeStorage.encryptString(s.password).toString('base64');
  }
  try {
    fs.mkdirSync(path.dirname(settingsPath()), { recursive: true });
    fs.writeFileSync(settingsPath(), JSON.stringify(out, null, 2), 'utf8');
  } catch (err) {
    console.error('保存设置失败', err);
  }
}

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

function createWindow() {
  win = new BrowserWindow({
    width: 760,
    height: 720,
    minWidth: 680,
    minHeight: 600,
    title: 'TopSAP 客户端',
    backgroundColor: '#0f1115',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  // 开发用：--screenshot=<路径> 渲染完成后截图并退出，便于无人值守验证界面
  const shotArg = process.argv.find((a) => a.startsWith('--screenshot='));
  if (shotArg) {
    const out = shotArg.split('=').slice(1).join('=');
    win.webContents.once('did-finish-load', () => {
      setTimeout(async () => {
        try {
          const img = await win.webContents.capturePage();
          fs.writeFileSync(out, img.toPNG());
        } catch (err) {
          console.error('截图失败', err);
        }
        app.quit();
      }, 1500);
    });
  }

  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  win.on('close', async (e) => {
    if (quitting) return;
    e.preventDefault();
    quitting = true;
    try {
      if (engine) await engine.disconnect({ silent: true });
    } catch { /* 忽略 */ }
    win.destroy();
    app.quit();
  });
}

function wireEngine() {
  engine = new Engine({ appRoot });

  engine.on('state', (s) => send('engine:state', s));
  engine.on('log', (line) => send('engine:log', line));
  engine.on('captcha', (c) => send('engine:captcha', { png: c.png.toString('base64') }));
  engine.on('stats', (s) => send('engine:stats', s));
  engine.on('error', (e) => send('engine:error', e.message));
}

app.whenReady().then(async () => {
  // 自检模式：不开窗口，验证虚拟网卡数据面后退出
  const stArg = process.argv.find((a) => a.startsWith('--selftest='));
  if (stArg) {
    const out = stArg.split('=').slice(1).join('=');
    const lines = [];
    const log = (m) => { lines.push(m); console.log(m); };
    try {
      await require('./selftest').run(log);
    } catch (err) {
      log('自检异常：' + err.message);
    }
    try { fs.writeFileSync(out, lines.join('\r\n'), 'utf8'); } catch { /* 忽略 */ }
    app.exit(0);
    return;
  }

  wireEngine();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  app.quit();
});

app.on('before-quit', async () => {
  if (engine) {
    try { await engine.disconnect({ silent: true }); } catch { /* 忽略 */ }
  }
});

// ---------- IPC ----------

ipcMain.handle('app:info', () => ({
  version: app.getVersion(),
  elevated: isElevated(),
  platform: process.platform,
  arch: process.arch,
}));

ipcMain.handle('settings:load', () => loadSettings());
ipcMain.handle('settings:save', (_e, s) => { saveSettings(s); return true; });

ipcMain.handle('auth:login', async (_e, form) => {
  try {
    const s = await engine.login(form);
    saveSettings({ ...form, remember: !!form.remember });
    return {
      ok: true,
      session: {
        user: s.userName,
        vip: s.vip,
        mask: s.vipMask,
        dns1: s.dns1,
        dns2: s.dns2,
        routes: s.routes.length,
        hosts: s.hosts.length,
        acl: s.acl.length,
      },
    };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('auth:captcha', (_e, code) => engine.submitCaptcha(code));

ipcMain.handle('conn:connect', async () => {
  try {
    await engine.connect();
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('conn:disconnect', async () => {
  try {
    await engine.disconnect();
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('dialog:openLog', async () => {
  const p = path.join(app.getPath('userData'), 'client.log');
  if (fs.existsSync(p)) shell.openPath(p);
  return p;
});

ipcMain.handle('app:selftest', async () => {
  const lines = [];
  let ok = false;
  try {
    ok = await require('./selftest').run((m) => {
      lines.push(m);
      send('engine:log', m);
    });
  } catch (err) {
    lines.push('自检异常：' + err.message);
  }
  return { ok, lines };
});
