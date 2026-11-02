'use strict';
/**
 * 隧道层：一条通往网关的 TLS 长连接，之上承载 16 字节头的自定义帧。
 *
 * 建立过程：
 *   1. TLS 连接（网关证书多为自签/过期，不校验链）
 *   2. 发送 HTTP CONNECT 前言，让网关进入隧道模式
 *   3. 发送登录帧（携带 session_id）
 *   4. 收到 type=2 确认帧后，发送 type=7 通知帧
 *   5. 之后双向收发 type=15 的 IPv4 报文
 */
const tls = require('tls');
const { EventEmitter } = require('events');
const proto = require('./protocol');

const CONNECT_PREFACE =
  'CONNECT 127.0.0.1:4430 HTTP/1.1\r\n' +
  'host:127.0.0.1\r\n' +
  'User-Agent: VONE-NA,WINDOWS,NULL,TOPCLINET,NULL\r\n' +
  'Proxy-Connection: Keep-Alive\r\n\r\n';

class Tunnel extends EventEmitter {
  constructor(session, opts = {}) {
    super();
    this.session = session;
    this.host = session.gateway;
    this.port = Number(session.port) || 443;
    this.connectTimeout = opts.connectTimeout || 20000;
    this.socket = null;
    this.parser = new proto.FrameParser();
    this.state = 'idle';
    this.bytesUp = 0;
    this.bytesDown = 0;
    this.ackTimer = null;
  }

  connect() {
    if (this.socket) throw new Error('隧道已连接');
    this.state = 'connecting';

    const sock = tls.connect({
      host: this.host,
      port: this.port,
      rejectUnauthorized: false,
      servername: undefined, // 客户端不发 SNI，与官方客户端保持一致
    });
    this.socket = sock;

    sock.setNoDelay(true);
    sock.setKeepAlive(true, 15000);

    const timer = setTimeout(() => {
      if (this.state !== 'ready') {
        this.emit('error', new Error('隧道握手超时'));
        this.destroy();
      }
    }, this.connectTimeout);

    sock.on('secureConnect', () => {
      this.emit('log', `隧道 TLS 已建立（${sock.getProtocol() || 'TLS'}）`);
      sock.write(Buffer.from(CONNECT_PREFACE, 'latin1'));
      sock.write(proto.buildLoginFrame(this.session.sessionId));
      this.state = 'handshaking';
      this.emit('log', `已发送登录帧（session=${this.session.sessionId}）`);
    });

    sock.on('data', (chunk) => this._onData(chunk));

    sock.on('error', (err) => {
      clearTimeout(timer);
      this.emit('error', err);
    });

    sock.on('close', () => {
      clearTimeout(timer);
      if (this.ackTimer) clearTimeout(this.ackTimer);
      const was = this.state;
      this.state = 'closed';
      this.socket = null;
      this.emit('close', was);
    });

    // 兜底：即便没收到确认帧，也不能永远卡住
    this.ackTimer = setTimeout(() => {
      if (this.state === 'handshaking') {
        this.emit('error', new Error('未收到隧道登录确认'));
        this.destroy();
      }
    }, this.connectTimeout);
  }

  _onData(chunk) {
    let frames;
    try {
      frames = this.parser.push(chunk);
    } catch (err) {
      this.emit('error', err);
      this.destroy();
      return;
    }

    for (const f of frames) {
      if (f.type === proto.MSG_ACK) {
        if (this.state === 'handshaking') {
          clearTimeout(this.ackTimer);
          this.state = 'ready';
          this.socket.write(proto.buildNotifyFrame());
          this.emit('ready');
        }
        continue;
      }

      if (f.type === proto.MSG_DATA && proto.isIPv4(f.payload)) {
        this.bytesDown += f.payload.length;
        this.emit('packet', Buffer.from(f.payload));
        continue;
      }

      if (f.payload.length) {
        const text = f.payload.toString('utf8').replace(/[^\x20-\x7e]/g, '.');
        this.emit('log', `控制帧 type=${f.type} dir=${f.dir} len=${f.payload.length} ${text.slice(0, 160)}`);
      }
    }
  }

  /** 发送一个 IPv4 报文 */
  sendPacket(packet) {
    if (this.state !== 'ready' || !this.socket) return false;
    this.socket.write(proto.buildDataFrame(packet));
    this.bytesUp += packet.length;
    return true;
  }

  destroy() {
    if (this.ackTimer) clearTimeout(this.ackTimer);
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
    this.state = 'closed';
  }
}

module.exports = { Tunnel };
