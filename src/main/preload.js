'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  info: () => ipcRenderer.invoke('app:info'),
  loadSettings: () => ipcRenderer.invoke('settings:load'),
  saveSettings: (s) => ipcRenderer.invoke('settings:save', s),
  login: (form) => ipcRenderer.invoke('auth:login', form),
  captcha: (code) => ipcRenderer.invoke('auth:captcha', code),
  connect: () => ipcRenderer.invoke('conn:connect'),
  disconnect: () => ipcRenderer.invoke('conn:disconnect'),
  openLog: () => ipcRenderer.invoke('dialog:openLog'),
  selftest: () => ipcRenderer.invoke('app:selftest'),
  on: (channel, cb) => {
    const allowed = ['engine:state', 'engine:log', 'engine:captcha', 'engine:stats', 'engine:error'];
    if (!allowed.includes(channel)) return () => {};
    const handler = (_e, payload) => cb(payload);
    ipcRenderer.on(channel, handler);
    return () => ipcRenderer.removeListener(channel, handler);
  },
});
