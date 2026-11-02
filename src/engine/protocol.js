'use strict';
/**
 * TopSAP 隧道分帧协议
 *
 * 16 字节固定头：
 *   +0..3   保留（0）
 *   +4..7   消息类型   2=登录确认  7=通知  15=IPv4 数据
 *   +8..11  载荷长度（大端）
 *   +12..15 方向       1=上行  0=下行
 *
 * 登录帧载荷（328 字节）：4 字节常量 0x04 + 68 字节零 + session_id + 补零
 */

const MSG_LOGIN = 1;
const MSG_ACK = 2;
const MSG_NOTIFY = 7;
const MSG_DATA = 15;

const DIR_UP = 1;
const DIR_DOWN = 0;

const LOGIN_PAYLOAD_SIZE = 328;
const SESSION_OFFSET = 72;

function buildFrame(type, payload, dir) {
  const body = payload || Buffer.alloc(0);
  const head = Buffer.alloc(16);
  head.writeUInt32BE(0, 0);
  head.writeUInt32BE(type, 4);
  head.writeUInt32BE(body.length, 8);
  head.writeUInt32BE(dir, 12);
  return Buffer.concat([head, body]);
}

/** 建立隧道时发送的登录帧：把 session_id 填进固定结构 */
function buildLoginFrame(sessionId) {
  if (!sessionId) throw new Error('session_id 为空');
  const payload = Buffer.alloc(LOGIN_PAYLOAD_SIZE);
  payload.writeUInt32BE(4, 0);
  const idBuf = Buffer.from(sessionId, 'latin1');
  if (idBuf.length > LOGIN_PAYLOAD_SIZE - SESSION_OFFSET) throw new Error('session_id 过长');
  idBuf.copy(payload, SESSION_OFFSET);
  return buildFrame(MSG_LOGIN, payload, DIR_UP);
}

/** 登录确认后立刻发的通知帧（8 字节零载荷） */
function buildNotifyFrame() {
  return buildFrame(MSG_NOTIFY, Buffer.alloc(8), DIR_UP);
}

/** 承载一个完整 IPv4 报文 */
function buildDataFrame(ipPacket) {
  return buildFrame(MSG_DATA, ipPacket, DIR_UP);
}

/**
 * 流式拆帧。TCP 上帧可能被切开或粘连，这里做累积解析。
 */
class FrameParser {
  constructor() {
    this.buf = Buffer.alloc(0);
    this.maxFrame = 65535 + 16;
  }

  push(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    const out = [];
    while (this.buf.length >= 16) {
      const len = this.buf.readUInt32BE(8);
      if (len > this.maxFrame) throw new Error(`帧长度异常: ${len}`);
      if (this.buf.length < 16 + len) break;
      const frame = {
        type: this.buf.readUInt32BE(4),
        dir: this.buf.readUInt32BE(12),
        payload: this.buf.subarray(16, 16 + len),
      };
      this.buf = this.buf.subarray(16 + len);
      out.push(frame);
    }
    return out;
  }

  reset() {
    this.buf = Buffer.alloc(0);
  }
}

/** 判断载荷是不是一个 IPv4 报文（版本号 4 且长度足够） */
function isIPv4(buf) {
  return buf.length >= 20 && (buf[0] >> 4) === 4;
}

module.exports = {
  MSG_LOGIN, MSG_ACK, MSG_NOTIFY, MSG_DATA, DIR_UP, DIR_DOWN,
  buildFrame, buildLoginFrame, buildNotifyFrame, buildDataFrame,
  FrameParser, isIPv4,
};
