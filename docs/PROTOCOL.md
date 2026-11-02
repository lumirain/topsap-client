# TopSAP (NGVONE) 接入协议说明

本文档由黑盒抓包 + 静态分析 + 真机验证得出，全部结论均经过实测。
适用于天融信 NGVONE 系列 SSL VPN 网关（`vpn_version: ngvone`）。

---

## 1. 总体流程

```
客户端                                    网关
  │  POST /vone/login/auth_param           │  获取网关能力（无需认证）
  │ ──────────────────────────────────────▶│
  │  GET  /vone/login/gid                  │  取图形验证码（种 cgid Cookie）
  │ ──────────────────────────────────────▶│
  │  POST /vone/login/user_pswd            │  提交凭据，返回会话 + 网络参数
  │ ──────────────────────────────────────▶│
  │  TLS connect :4431                     │  另建长连接作为隧道
  │ ──────────────────────────────────────▶│
  │  登录帧（含 session_id）                  │
  │ ──────────────────────────────────────▶│
  │                          ◀──────────────│  确认帧
  │  通知帧                                  │
  │ ──────────────────────────────────────▶│
  │  IPv4 数据帧 ⇄ IPv4 数据帧               │  隧道内直接承载原始 IP 包
```

认证用短连接，隧道用另一条长连接。两者同一端口（默认 4431）。

---

## 2. HTTP 接口

### 2.1 网关能力：`POST /vone/login/auth_param`

无需认证，返回网关全部配置。响应是宽松 JS 对象（键名不带引号），需容错解析。

关键字段：

| 字段 | 含义 |
|---|---|
| `vpn_version` | `ngvone` / `sm2plusvone` 等，决定协议分支 |
| `cipher_type` | `0` = 标准加密（TLS 承载明文 IP 包）；`1` 及以上走国密 |
| `auth_port` / `data_port` | 认证与数据端口 |
| `auth_protocol` / `data_protocol` | `0` = TCP |
| `cert_type` | 证书类型 |
| `ca_list` | 网关 CA 名称 |
| `gid` | 验证码策略：`off` / `on` / `auto`（失败若干次后要求） |
| `oauth2_switch` / `appid` / `agentid` | 企业微信扫码登录配置 |

### 2.2 图形验证码：`GET /vone/login/gid`

- 返回 `image/png`，同时 `Set-Cookie: cgid=<base64 16 字节>`
- 验证码需人工识别，有效期很短（约 30 秒），且与 `cgid` 绑定

### 2.3 登录：`POST /vone/login/user_pswd`

```
Content-Type: application/x-www-form-urlencoded
User-Agent: VONE-AUTH,WINDOWS,NULL,TOPCLINET,NULL
Cookie: topsecsvuilanguage=chinese; sv_un=<user>; login_err_num=0;
        topsecsvportalstyle=style1; topsecsvportalname=default; cgid=<cgid>;

U=<user>&P=<password>&Gid=<captcha>&HASH=<64 hex>&S_CODE=<base64 16B>
```

要点：

- **`U` 与 `P` 都是明文**（仅做 URL 编码）。客户端前端那套 `Base64` / `JSEncrypt(RSA)`
  在 `vpn_version: ngvone` 下**不会出现在报文里**——原生层会用内置私钥解掉 RSA。
- **`HASH` 服务端不校验内容**，但字段必须存在且为 64 位十六进制。
  实测传全 `0` 也能正常返回完整配置。
- **`S_CODE`** 为 16 字节随机数的 Base64，同样只需存在。
- 缺 `HASH` / `S_CODE` 时服务端会返回一个**残缺会话**：`Ret:0` 有 `session_id`，
  但响应里没有 `user_param` / `net_param`，隧道会转而索取配置（见 §4）。

成功响应（节选）：

```javascript
{
  user_param: {
    topafasfasfassession_id: "742&d5bab619aaaa90e",
    username: "temp999",
    alg: "standard",            // 加密算法族
    sm_priority: "SM4",         // 国密优先算法
    spa_key: "2BA465A3...",     // fwknop 单包授权密钥（网关下发）
    netacc: "on",               // 是否启用网络接入
    vpn_version: "ngvone"
  },
  net_param: {
    vip_v4: "172.21.9.160",     // 分配给本机的虚拟 IP
    vip_mask: "255.255.248.0",
    dns1_v4: "10.22.50.5",
    dns2_v4: "10.22.50.6",
    acl_permit: 1,
    acl_check_switch: 1
  },
  Ret: 0
}
```

### 2.4 注销：`POST /vone/login/logout`

带 `Cookie: topafasfasfassession_id=<sid>`，返回 `{Ret:0}`。
网关默认限制**单账号单会话**，重复登录返回 `Ret:-40077 不允许多点登录`。

---

## 3. 隧道帧格式

TLS 建立后先发一个 HTTP 风格的前导（沿用旧版本兼容）：

```
CONNECT 127.0.0.1:4430 HTTP/1.1
host:127.0.0.1
User-Agent: VONE-NA,WINDOWS,NULL,TOPCLINET,NULL
Proxy-Connection: Keep-Alive
```

随后进入二进制分帧。**每帧固定 16 字节头 + 载荷**：

```
偏移    长度   含义
0x00    8    报文类型（大端）
0x08    4    载荷长度（大端）
0x0C    4    方向：1 = 客户端 → 网关，0 = 网关 → 客户端
```

### 3.1 报文类型

| 类型 | 名称 | 载荷 |
|---|---|---|
| 1 | 登录 | 328 字节定长结构，偏移 `0x48` 处放 `session_id` 字符串 |
| 2 | 确认 | 空 |
| 7 | 通知 | 8 字节全 0 |
| 15 | IPv4 数据 | 完整 IPv4 报文（含 IP 头） |

### 3.2 登录帧结构（328 字节载荷）

```
+0x00  00 00 00 04        客户端类型（Windows = 4）
+0x04  00 ...             保留，全 0
+0x48  "742&d5bab6..."    会话 ID，ASCII，以 0 结尾
+...   全 0
```

### 3.3 握手时序

```
客户端                                   网关
  │  帧(type=1, 登录帧)                     │
  │ ──────────────────────────────────────▶│
  │                       ◀─────────────────│  帧(type=2, 空载荷)
  │  帧(type=7, 8 字节 0)                    │
  │ ──────────────────────────────────────▶│
  │  帧(type=15, IPv4 包)                    │
  │ ──────────────────────────────────────▶│
  │                       ◀─────────────────│  帧(type=15, IPv4 包)
```

实测一次完整的 DNS 往返：

```
-> type=15  IPv4 172.21.9.160 -> 10.22.50.5  UDP 46341 -> 53   (查询 www.sunline.cn)
<- type=15  IPv4 10.22.50.5 -> 172.21.9.160  UDP 53 -> 46855  (应答，76 字节)
```

隧道内承载的就是**原始 IPv4 报文**，没有额外加密（`cipher_type=0` 时）。
国密模式下由 `cipher_type` 与 `sm_priority` 决定是否叠加 SM4，本网关为 0。

---

## 4. 残缺会话与 `req_packet`

若登录响应缺少 `net_param`（例如未带 `HASH` / `S_CODE`），隧道会在确认帧后下发：

```json
{ "req_packet": 45, "session_id": "..." }
```

该报文用于向网关索取网络参数，载荷结构尚未解析。
正常登录（带齐字段）不会走到这条分支，因此**优先保证登录报文完整**。

---

## 5. 客户端侧要做的事

1. 用 `net_param` 配置虚拟网卡：IP = `vip_v4`，掩码 = `vip_mask`，DNS = `dns1_v4`/`dns2_v4`
2. 从网卡读出 IP 包 → 加 16 字节头（type=15, dir=1）→ 写入 TLS
3. 从 TLS 读帧 → type=15 时剥掉 16 字节头 → 写入网卡
4. 保活：定时发送 type=7 通知帧
5. 断线：`POST /vone/login/logout` 并复位网卡

---

## 6. 已验证的边界

- 网关不校验证书有效期（实测真实证书已过期仍可连接），也不校验 SNI。
- 网关不校验 `HASH` 内容，仅校验字段存在。
- 口令在应用层为明文，机密性完全依赖 TLS。
- 单账号单会话，重登需先注销。
