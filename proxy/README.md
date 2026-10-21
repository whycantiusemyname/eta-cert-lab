# Eta MITM proxy（通用版）

按**特征**自动识别完整性验证请求，按 **SNI** 动态签证书，其它流量原样转发。不依赖任何特定域名。

## 它怎么"自动识别"

| 特征 | 判断依据 |
|---|---|
| 请求带 JWE token | URL 里出现 `token=eyJ` |
| 路径像校验接口 | 路径含 `/api/check` |
| 响应含判定字段 | 响应 JSON 里有 `deviceRecognitionVerdict` |

命中任一 → 返回伪造的"全绿"JSON；否则 → 转发到真实服务器（可走上游代理）。

## 用法

```sh
python3 eta_mitm.py \
  --listen 0.0.0.0:8443 \
  --ca-cert samples/demo-ca.pem \
  --ca-key  samples/demo-ca.key \
  --upstream 127.0.0.1:7890        # 可选：转发时走 Clash 的混合端口
```

然后把流量指过来：

```sh
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 8443
# 或只针对某个 uid：
iptables -t nat -A OUTPUT -m owner --uid-owner 10495 -p tcp --dport 443 -j REDIRECT --to-ports 8443
```

## 两个关键点

**1. SNI 必须在 wrap 之前"看"到，不能"读走"**

```python
peeked = sock.recv(16384, socket.MSG_PEEK)   # 只看不取
sni = parse_sni(peeked)
tls = ctx.wrap_socket(sock, server_side=True) # 原始数据还在内核缓冲里
```

如果先 `recv()` 把 ClientHello 吃掉，握手就会卡住——这是最容易踩的坑。

**2. 伪造响应要匹配客户端的解析习惯**

不同 app 对返回结构的期待不同，例如：

```json
{"deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_BASIC_INTEGRITY","MEETS_DEVICE_INTEGRITY","MEETS_STRONG_INTEGRITY"]}}
```

有些客户端只认顶层 `deviceIntegrity`，不认 Google 原生的 `tokenPayloadExternal` 包装。改这里就能适配。

## 限制

- 只处理 HTTP/1.1（`ALPN: http/1.1`）；HTTP/2 需要额外实现；
- 每条连接处理一个请求（`Connection: close`），不复用连接；
- ECH（Encrypted Client Hello）会隐藏 SNI，此方案失效。
