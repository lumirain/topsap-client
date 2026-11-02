# TopSAP Client

天融信 NGVONE / TopSAP SSL VPN 的开源替代客户端。**纯协议实现**，不依赖厂商任何二进制。

原客户端是一套 Electron 界面 + 常驻服务 + 内核驱动的组合，界面层问题较多。本项目只做一件事：把已经摸清的协议用一份可读的代码实现出来，配一个稳定的界面，出安装包。

> 协议细节见 [docs/PROTOCOL.md](docs/PROTOCOL.md)。

---

## 功能

- 账号密码 + 图形验证码登录
- 自动读取网关下发的虚拟 IP、DNS、路由与内网主机名
- 自建虚拟网卡（Wintun），分流隧道
- 实时显示上下行流量、收发包数、连接时长
- 断开时按清单撤销全部系统改动（路由、hosts、DNS），不留残留
- 支持记住密码（Windows DPAPI 加密存储）

---

## 安装

从 Releases 下载 `TopSAP Client-x.y.z-setup.exe` 直接安装。

安装时会请求管理员权限，这是必要的：创建虚拟网卡、改路由表、写 hosts 都需要提权。
安装后的主程序清单为 `requireAdministrator`，之后每次启动 Windows 会自动提权。

**卸载**：控制面板卸载即可。程序不会留下虚拟网卡、路由或 hosts 残留——断开连接时已经清理干净。

---

## 使用

1. 启动程序（会自动请求管理员权限）
2. 填网关地址、端口、账号、密码
3. 点「连接」，弹出验证码后输入
4. 状态变为「已连接」即可访问内网

断开点「断开」按钮，或直接关闭窗口（关闭时会自动断开并清理）。

**连不上时先点「网卡自检」**：它会临时创建一块虚拟网卡，用回环 ICMP 验证「网卡→应用」和「应用→网卡」两个方向，几秒钟出结果。这一步不碰网关，能把网卡驱动问题和协议问题区分开。

### 仅验证协议栈

不需要管理员权限：

```bash
node scripts/probe.js vpn.example.com 443 用户名 密码
```

验证码会保存为 `captcha.png`，看清后写入 `.code.txt` 即可继续。
成功时会打印隧道回来的 IP 报文，说明登录 + 握手 + 数据面都通。

---

## 从源码构建

要求：Node.js 18+、Windows x64。

```bash
npm install
npm start        # 开发运行
npm run dist     # 打 NSIS 安装包，产物在 dist/
```

> 国内网络建议设置镜像：
> `set ELECTRON_MIRROR=https://registry.npmmirror.com/-/binary/electron/`

---

## 架构

```
src/
  main/
    main.js          Electron 主进程：窗口、IPC、设置存储、生命周期
    preload.js       contextBridge 暴露的白名单 API
  renderer/
    index.html       界面结构
    app.js           界面逻辑
    style.css        样式
  engine/
    auth.js          登录：auth_param → gid → user_pswd，响应归一化
    protocol.js      16 字节帧头编解码、流式拆帧
    tunnel.js        TLS 长连接 + 握手状态机
    tun.js           Wintun 绑定（koffi FFI），读循环与写包
    netcfg.js        网卡地址、路由注入、hosts 覆盖、清理
    engine.js        连接生命周期编排
assets/
  wintun/wintun.dll  微软签名的虚拟网卡驱动（随包分发）
```

数据流：

```
系统网络栈 ──▶ Wintun 网卡 ──▶ tun.readLoop ──▶ tunnel.sendPacket ──▶ TLS ──▶ 网关
系统网络栈 ◀── Wintun 网卡 ◀── tunnel 'packet' ◀── 拆帧 ◀── TLS ◀── 网关
```

---

## 已知限制

- 仅支持 `vpn_version=ngvone` 的网关；国密网关（`sm2plusvone`）未实现
- 未实现 SPA 单包授权（标准网关不启用）
- 不做会话恢复，断线后重新握手
- 仅 Windows x64

---

## 安全说明

1. **不校验证书链**：网关证书普遍自签或已过期，原始客户端也不校验。这意味着在有中间人的网络中，攻击者可以冒充网关。这是兼容性代价，请勿在不可信网络中使用。
2. **登录凭据以明文经过 TLS**：网关要求如此。安全边界完全依赖 TLS 通道。
3. **需要管理员权限**：这是修改系统网络配置的前提，无法避免。程序只做 README 中列出的网络配置改动，不做其他系统修改。

---

## 许可

MIT。见 [LICENSE](LICENSE)。

本项目仅用于与自有网关对接、以及在授权范围内替换有缺陷的官方客户端。请勿用于未经授权的访问。
