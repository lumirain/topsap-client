# TopSAP / 天融信 NGVONE 协议说明

本文件记录的是**实测确认**的行为，不是推测。凡是标注"推断"的地方都单独说明了依据。

目标固件：TopSAP 客户端 3.6.4.16.64.1（天融信 NGVONE，`vpn_version=ngvone`、`cipher_type=0` 的网关）。

---

## 1. 传输层前提

网关的 HTTPS 使用自签或已过期证书，官方客户端**不校验证书链**，且**不发送 SNI**。
因此本客户端连接时使用 `rejectUnauthorized: false` 并省略 `servername`。

> 安全性说明：这一层没有身份认证能力。在有中间人的网络里，任何人都能冒充网关。
> 这是原始实现的设计，本客户端为保持兼容而沿用，但在 README 中明确提示。

---

## 2. 登录接口

公共请求头：

```
User-Agent: VONE-AUTH,WINDOWS,NULL,TOPCLINET,NULL
```

### 2.1 能力探测

```
POST /vone/login/auth_param
```

无需认证。返回网关配置（伪 JSON，键名不带引号）：

| 字段 | 说明 |
| --- | --- |
| `auth_port` / `data_port` | 认证端口 / 数据端口 |
| `vpn_version` | `ngvone`（标准）或 `sm2plusvone`（国密） |
| `cipher_type` | `0` 表示未启用国密信道加密 |
| `captcha` | 是否需要图形验证码 |

### 2.2 取验证码

```
GET /vone/login/gid
```

返回 PNG，同时 `Set-Cookie: cgid=...`。后续登录必须带上该 cookie，验证码与 `cgid` 绑定。

### 2.3 提交登录

```
POST /vone/login/user_pswd
Content-Type: application/x-www-form-urlencoded
Cookie: cgid=...; topsecsvuilanguage=chinese

U=<账号>&P=<密码>&Gid=<验证码>&HASH=<64位十六进制>&S_CODE=<16字节随机数的Base64>
```

实测结论：

- **`U` 和 `P` 都是明文。** 前端 `sv_init.js` 里的 RSA + Base64 在 `ngvone` 路径下会被原生层解开，最终发出的是明文。对本网关而言那套加密只是混淆。
- **`HASH` 的内容不被校验。** 传 64 个 `0` 也能通过。可以推断该字段只在某些加固配置下参与校验，标准网关不检查。
- `S_CODE` 传任意 16 字节随机数的 Base64 即可。
- 参数中的 `+` 必须转义为 `%2B`，否则网关按 URL 解码会把 `+` 变成空格（官方客户端自己也踩过这个坑，报 `Ret=-7`）。

常见返回码：

| Ret | 含义 |
| --- | --- |
| `0` | 成功 |
| `-7` | 请求格式错误（多为 `+` 未转义） |
| `-40018` | 验证码错误 |
| `-40077` | 账号已在别处登录（单点） |
| `-40081` | 账号或密码错误 |

### 2.4 登录响应

响应是伪 JSON（键名无引号），包含 9 个顶层节点：

```
user_param  会话与账号属性
net_param   网络参数（虚拟 IP、掩码、DNS、隧道类型）
route_list  需要注入的路由前缀
acl_list    网关侧访问控制规则
dns_info    内网主机名映射
res_list    门户资源列表
sec_rule    终端合规规则
ErrMsg, Ret 结果
```

关键字段：

```
user_param.topafasfasfassession_id   会话 ID，形如 "470&bb70a290c038640"
user_param.spa_key                   SPA 单包授权密钥
net_param.vip_v4 / vip_mask          分配给本机的虚拟 IP 与掩码
net_param.dns1_v4 / dns2_v4          内网 DNS
net_param.tunnel_type                0=分流，1=全网
route_list[] {dest, mask}            需要走隧道的网段
dns_info.dns_list                    形如 "10.22.1.137 http://luban.example.com:3000"
acl_list[] {protocol, sport, dport, d_ip_v4, d_mask, action, week, start_tm, end_tm}
```

### 2.5 注销

```
POST /vone/login/logout
Cookie: topafasfasfassession_id=<会话ID>
```

返回 `{ Ret: 0 }`。不注销会占用账号的单点登录名额，下一次登录报 `-40077`。

---

## 3. 隧道协议

登录走 HTTPS 短连接；隧道是**另开一条 TLS 长连接**到同一端口，之上承载自定义二进制帧。

### 3.1 握手

```
TCP/TLS 连接 gateway:port
→ "CONNECT 127.0.0.1:4430 HTTP/1.1\r\nhost:127.0.0.1\r\n
   User-Agent: VONE-NA,WINDOWS,NULL,TOPCLINET,NULL\r\n
   Proxy-Connection: Keep-Alive\r\n\r\n"
→ 登录帧（见下）
← 确认帧 type=2
→ 通知帧 type=7，载荷 8 字节零
↔ 数据帧 type=15
```

登录帧载荷 328 字节，布局：

```
偏移 0   4 字节   常量 0x00000004
偏移 4   68 字节  全零
偏移 72  19 字节  会话 ID（ASCII，例如 "470&bb70a290c038640"）
其余      补零
```

### 3.2 帧格式

固定 16 字节头 + 载荷，全部大端：

```
+0..3    保留，恒为 0
+4..7    消息类型   1=登录  2=确认  7=通知  15=IPv4 数据
+8..11   载荷长度
+12..15  方向       1=上行（客户端→网关）  0=下行
```

`type=15` 的载荷就是一个**完整的 IPv4 报文**（从版本/IHL 开始，含 IP 头）。
数据面**没有任何额外加密**：`cipher_type=0` 的网关上，国密 SM4 信道不会被启用。

### 3.3 保活与断线

- 网关侧空闲超时由 `net_param.no_flow_timeout` 控制，`0` 表示不主动断开。
- 未观察到独立的心跳帧；周期性流量（TCP keepalive 或应用层流量）即可维持。
- 连接断开后需重新握手，会话 ID 可复用（同一会话内重连无需重新登录）。

---

## 4. 客户端网络模型

### 4.1 地址

虚拟网卡使用 `net_param.vip_v4` / `vip_mask`。MTU 取 1400（官方客户端行为）。

### 4.2 路由

官方客户端把 `acl_list` 逐条展开成 /32 路由（实测 22 条 ACL → 28 条路由）。
`route_list` 提供的是等价的网段聚合，本客户端直接使用它，代价是路由表更干净（5 条而非 28 条）。

**必须**为网关自身的 IP 加一条旁路路由（走物理默认网关），否则隧道连接会自己走进隧道形成环路。

### 4.3 DNS

- 内网主机名走 `dns_info.dns_list`，本质是 hosts 覆盖。本客户端写成 hosts 的独立段落，断开时整段移除。
- 网卡 DNS 设为 `dns1_v4`，让内网域名解析走隧道。不劫持全局 DNS，避免影响正常上网。

### 4.4 分流

`tunnel_type=0` 为分流：只把 `route_list` 里的网段打进隧道，其余流量走物理网络。
网关侧另有 `acl_list` 做二次管控，即使本地路由放通，未授权的目标也会被丢弃。

---

## 5. 与官方实现的差异

| 方面 | 官方客户端 | 本客户端 |
| --- | --- | --- |
| 虚拟网卡 | NDIS 小端口驱动 `TopvDev.sys`（`\\.\TOPVNIC`，重叠 I/O） | Wintun（微软签名驱动，用户态 DLL） |
| 路由来源 | 展开 ACL 成 /32 | 直接用 `route_list` 网段 |
| 进程模型 | Electron 界面 + `sv_service.exe`(LocalSystem) + `na_client.exe`，共享内存传 socket 句柄 | 单进程，全部逻辑在应用内 |
| 登录字段 | 前端 RSA/Base64 后由原生层解密 | 直接发明文（网关要的就是明文） |
| 证书校验 | 不校验证书链、不发 SNI | 相同（兼容性要求） |
| 国密 | 支持 SM2/SM4（`sm2plusvone` 网关） | 未实现，仅支持 `ngvone` |

---

## 6. 未实现 / 已知限制

1. **国密网关（`sm2plusvone`）不支持。** 只验证过 `vpn_version=ngvone`。
2. **SPA 单包授权未实现。** 登录响应会下发 `spa_key`，标准网关上不启用；若网关开启 SPA，需要先发 fwknop 敲门包。
3. **`acl_list` 只用于展示统计，未做本地过滤。** 实际管控由网关执行。
4. **UDP over TCP 的封装细节未知。** 实测隧道直接承载原始 IP 报文，未观察到额外封装头；若某类网关启用了封装，需要重新抓包确认。
5. **断线重连**为重新握手，不做会话恢复。
