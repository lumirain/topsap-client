'use strict';
/**
 * 引擎：把登录 / 隧道 / 网卡 / 路由 串成一条连接生命周期。
 *
 * 事件：
 *   'state'   { state, detail }
 *   'log'     string
 *   'captcha' { png: Buffer }
 *   'stats'   { up, down, duration, vip, routes }
 *   'error'   Error
 */
const { EventEmitter } = require('events');
const { AuthClient, normalizeLogin } = require('./auth');
const { Tunnel } = require('./tunnel');
const { TunDevice, resolveDll, ADAPTER_NAME } = require('./tun');
const { NetConfig } = require('./netcfg');

const STATE = {
  IDLE: 'idle',
  LOGIN: 'login',
  TUNNEL: 'tunnel',
  CONFIG: 'config',
  CONNECTED: 'connected',
  DISCONNECTING: 'disconnecting',
};

class Engine extends EventEmitter {
  constructor(opts = {}) {
    super();
    this.appRoot = opts.appRoot || process.cwd();
    this.tun = null;
    this.tunnel = null;
    this.net = null;
    this.auth = null;
    this.session = null;
    this.state = STATE.IDLE;
    this.startedAt = 0;
    this.statsTimer = null;
    this._pendingCaptcha = null;
    this._busy = false;
  }

  get stateLabel() {
    return {
      idle: '未连接',
      login: '正在登录',
      tunnel: '正在建立隧道',
      config: '正在配置网络',
      connected: '已连接',
      disconnecting: '正在断开',
    }[this.state] || this.state;
  }

  setState(state, detail) {
    this.state = state;
    this.emit('state', { state, label: this.stateLabel, detail: detail || '' });
  }

  log(msg) {
    const ts = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    this.emit('log', `[${ts}] ${msg}`);
  }

  /** 第一步：登录，拿到会话和网络参数。验证码通过 waitCaptcha 回传 */
  async login({ host, port, user, pass }) {
    if (this._busy) throw new Error('已有操作在进行中');
    this._busy = true;
    try {
      this.setState(STATE.LOGIN, '正在探测网关');
      this.auth = new AuthClient({ host, port, user, pass });

      const cfg = await this.auth.probe();
      const needCaptcha = cfg.captcha !== 0 && cfg.captcha !== '0';
      this.log(`网关能力探测完成${needCaptcha ? '，需要图形验证码' : ''}`);

      let code = '';
      if (needCaptcha) {
        this.setState(STATE.LOGIN, '正在获取验证码');
        const png = await this.auth.captcha();
        this.emit('captcha', { png });
        this.setState(STATE.LOGIN, '等待输入验证码');
        code = await this.waitCaptcha();
      }

      this.setState(STATE.LOGIN, '正在校验账号');
      const raw = await this.auth.submit(code);
      this.session = normalizeLogin(raw);
      this.session.gateway = host;
      this.session.port = Number(port);
      this.session.password = pass;

      if (!this.session.sessionId) throw new Error('网关未返回 session_id');
      this.log(`登录成功：${this.session.userName || user}，虚拟 IP ${this.session.vip}`);
      this.log(`下发路由 ${this.session.routes.length} 条、内网主机 ${this.session.hosts.length} 条、ACL ${this.session.acl.length} 条`);
      return this.session;
    } finally {
      this._busy = false;
    }
  }

  /** 由界面层调用，把用户输入的验证码交给 login() */
  submitCaptcha(code) {
    if (this._pendingCaptcha) {
      this._pendingCaptcha.resolve(String(code || '').trim());
      this._pendingCaptcha = null;
      return true;
    }
    return false;
  }

  waitCaptcha() {
    return new Promise((resolve, reject) => {
      this._pendingCaptcha = { resolve, reject };
      setTimeout(() => {
        if (this._pendingCaptcha) {
          this._pendingCaptcha.reject(new Error('验证码输入超时'));
          this._pendingCaptcha = null;
        }
      }, 120000);
    });
  }

  /** 第二步：建网卡 + 建隧道 + 注入路由 */
  async connect() {
    if (!this.session) throw new Error('尚未登录');
    if (this._busy) throw new Error('已有操作在进行中');
    this._busy = true;
    const s = this.session;

    try {
      this.setState(STATE.TUNNEL, '正在创建虚拟网卡');
      this.tun = new TunDevice(resolveDll(this.appRoot)).open();
      this.tun.on('error', (e) => this.log('网卡异常：' + e.message));
      this.log(`虚拟网卡已就绪：${ADAPTER_NAME}`);

      this.setState(STATE.CONFIG, '正在配置网卡地址');
      this.net = new NetConfig(ADAPTER_NAME);
      await this.net.configureInterface(s.vip, s.vipMask);
      this.net.bypassGateway(s.gateway);
      this.log(`网卡地址 ${s.vip} / ${s.vipMask}，MTU 1400`);

      this.setState(STATE.TUNNEL, '正在连接网关');
      this.tunnel = new Tunnel(s);
      this.tunnel.on('log', (m) => this.log(m));
      this.tunnel.on('error', (e) => {
        this.log('隧道错误：' + e.message);
        this.emit('error', e);
      });
      this.tunnel.on('close', () => {
        if (this.state === STATE.CONNECTED) {
          this.log('隧道已断开');
          this.emit('error', new Error('隧道连接被中断'));
        }
      });

      await new Promise((resolve, reject) => {
        const onReady = () => { cleanup(); resolve(); };
        const onErr = (e) => { cleanup(); reject(e); };
        const cleanup = () => {
          this.tunnel.off('ready', onReady);
          this.tunnel.off('error', onErr);
        };
        this.tunnel.once('ready', onReady);
        this.tunnel.once('error', onErr);
        this.tunnel.connect();
      });

      this.setState(STATE.CONFIG, '正在注入路由');
      const n = this.net.addRoutes(s.routes);
      this.net.setDns(s.dns1);
      const h = this.net.applyHosts(s.hosts);
      this.log(`已注入 ${n} 条路由，写入 ${h} 条 hosts 记录，DNS ${s.dns1}`);

      // 双向数据泵
      this.tunnel.on('packet', (pkt) => {
        if (this.tun) this.tun.write(pkt);
      });
      this.tun.readLoop((pkt) => {
        if (this.tunnel) this.tunnel.sendPacket(pkt);
      }).catch((e) => this.log('网卡读循环结束：' + e.message));

      this.startedAt = Date.now();
      this.setState(STATE.CONNECTED);
      this.statsTimer = setInterval(() => this.emitStats(), 1000);
      this.emitStats();
      return true;
    } catch (err) {
      this.log('连接失败：' + err.message);
      await this.disconnect({ silent: true });
      throw err;
    } finally {
      this._busy = false;
    }
  }

  async disconnect({ silent = false } = {}) {
    if (this.state === STATE.IDLE && !this.tun && !this.tunnel) return;
    this.setState(STATE.DISCONNECTING);
    if (this.statsTimer) { clearInterval(this.statsTimer); this.statsTimer = null; }

    if (this.tunnel) {
      try { this.tunnel.destroy(); } catch { /* 忽略 */ }
      this.tunnel = null;
    }
    if (this.net) {
      try { this.net.cleanup(); } catch { /* 忽略 */ }
      this.net = null;
    }
    if (this.tun) {
      try { this.tun.close(); } catch { /* 忽略 */ }
      this.tun = null;
    }
    if (this.auth && this.session && this.session.sessionId) {
      try { await this.auth.logout(this.session.sessionId); } catch { /* 忽略 */ }
    }
    this.startedAt = 0;
    if (!silent) this.log('已断开并恢复网络配置');
    this.setState(STATE.IDLE);
  }

  emitStats() {
    if (!this.tunnel) return;
    this.emit('stats', {
      up: this.tunnel.bytesUp,
      down: this.tunnel.bytesDown,
      packetsIn: this.tun ? this.tun.packetsIn : 0,
      packetsOut: this.tun ? this.tun.packetsOut : 0,
      duration: this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1000) : 0,
      vip: this.session ? this.session.vip : '',
      routes: this.net ? this.net.injected.filter((i) => i.kind === 'route').length : 0,
    });
  }
}

module.exports = { Engine, STATE };
