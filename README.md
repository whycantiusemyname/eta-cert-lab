# Eta Cert Lab (LSPosed)

按**应用作用域**生效的 TLS 中间人实验模块。只对你在 LSPosed 里勾选的 app 生效，全部逻辑跑在目标进程内，不需要 iptables，也不需要外部代理。

```
app ──TCP/443──> [Socket.connect 改写] ──> 进程内 TLS 服务 ──TLS──> 真实服务器
                                             │
                                             └─ 读 SNI → 用泄漏的 eMudhra 中间 CA 现签 leaf → 原样转发
```

| 组件 | 作用 |
|---|---|
| **LSPosed 模块** | 进程内 TLS 服务 + 按 SNI 现签证书 + 绕过系统公钥黑名单 |
| `proxy/`、`tools/` | 早期外部代理方案，已不是主路径，仅留作参考 |

## 为什么需要证书

app 会验证服务器证书是否链到系统信任库。三种情况实测结果：

| 出示的证书 | app 反应 |
|---|---|
| 自签测试 CA | `certificate_unknown`（链不认识） |
| eMudhra 泄漏链 | `Certificate blocklisted by public key`（链认了，被黑名单拦） |
| eMudhra 链 + 模块绕黑名单 | 握手成功，app 接受连接 |

所以证书的作用是：**让 app 相信"我还在跟真后端说话"**。没有它，中间人连握手都过不去。

## 模块做什么

1. **进程内 MITM**：hook `java.net.Socket.connect`，**只**把目标域名的 443 连接改写到模块自己起的本地 TLS 端口（随机端口，只监听 127.0.0.1）；其他域名的连接原样直连，不经过任何中转；
2. **按 SNI 现签 leaf**：自定义 `X509ExtendedKeyManager`，在 `chooseServerAlias` 里从 handshake session 取 SNI，用泄漏的 `EM OV TLS CA - G3C`（`d=4`）签证书；
3. **组完整链**：发给客户端的是
   ```
   leaf(CN=<host>)
     ← EM OV TLS CA - G3C          (assets/emudhra)
       ← emSign Root TLS CA - G3   (交叉证书)
         ← emSign ECC Root CA - G3 (设备信任库里的根)
   ```
   所以客户端用**系统信任库**就能验证通过，不需要安装任何自签 CA；
4. **绕过黑名单**：hook `com.android.org.conscrypt.CertBlocklistImpl#isPublicKeyBlockListed` / `#isSerialNumberBlockListed`，返回 false；
5. **纯转发**：请求原样转发给真实服务器（强制 `Connection: close`，读完整响应后关闭），不修改任何响应内容；
6. **兜底 CA 注入**：hook `SSLContext.init`，把 `X509TrustManager` 包一层——原生校验失败时再用内置 demo CA 做一次 PKIX 校验（MITM 走真链时用不到）。

### 内置的 eMudhra 弱私钥

```
EM-DV-TLS-CA-G3B=156  EM-DV-TLS-CA-G3C=230
EM-EV-TLS-CA-G3B=115  EM-EV-TLS-CA-G3C=56
EM-OV-CS-CA-G3B=66    EM-OV-CS-CA-G3C=237
EM-OV-TLS-CA-G3B=155  EM-OV-TLS-CA-G3C=4
```

`app/src/main/assets/emudhra/` 里是这 8 张中间 CA 的**公开证书**以及把它们接到信任根的交叉证书，只用于组链。

## 分流规则

所有 443 连接都先接到本地——TCP 层只认 IP，这里放行就会漏。但接住之后**不盲目终结 TLS**：先读 ClientHello、解析出 SNI，再决定这条连接的命运。

| SNI | 处理 |
|---|---|
| 命中 `target.txt` | 本地终结 TLS，用泄漏的 eMudhra 中间 CA 现签 leaf，请求解析后原样转发 |
| 其他域名 | 把已读的 ClientHello 连同后续字节在 **TCP 层拼接**到真实服务器，TLS 全程端到端 |
| 解析不出 SNI，也没有已知域名 | 断开并记日志，不猜 |

所以“其他流量透传”是真的透传：证书不换、pinning 不受影响、WebSocket/gRPC 这类长连接照常工作，代价只是多一跳 loopback。

默认只拦 `integrity.1nikolas.dev`。改范围写目标 app 私有目录下的 `files/eta-cert-lab/target.txt`，一行一个，`#` 注释：

```
integrity.1nikolas.dev
*.1nikolas.dev
playintegrity.googleapis.com
```

- `*.example.com` 同时匹配子域和裸域；
- 只写一行 `*` 表示所有连接都终结 TLS（调试用，会碰坏 pinning）。

另外有一个纯优化：如果 IP 反查能确定某个连接**不是**目标，就在 TCP 层直接放行，省掉 loopback 一跳；反查不出来时一律接住交给 SNI 判断。这个优化永远不会导致漏拦，最坏情况只是多一跳。

## 使用

1. 安装 APK，在 LSPosed 里启用模块并勾选目标 app；
2. **强制停止目标 app 再打开**（hook 只在进程启动时安装）；
3. 触发 app 的完整性检查，LSPosed 日志会出现：

```
EtaCertLab: loaded in <package>
EtaCertLab: mitm server on 127.0.0.1:xxxxx signer=EM-OV-TLS-CA-G3C
EtaCertLab: signed <host>
EtaCertLab: PASS <host> GET /api/check?token=eyJ...
```

如果日志里出现 `signer verified:` 说明私钥与证书匹配成功；出现 `forward failed` 说明该域名的网络不通（先确认代理/VPN 正常）。

## 已验证

- 8 张中间 CA 的私钥都是从证书公钥反推的单个小整数（`key_matches_cert=True`）；
- 用 `d=4` 现签的 leaf 组上述三级链，用**设备真实信任库的 emSign ECC Root CA - G3** 做 anchor 跑 PKIX：链验证通过，EKU（serverAuth）路径检查通过；
- 8 张公钥的 SPKI SHA-1 全部在 `/data/misc/keychain/pubkey_blacklist.txt` 里，hook 掉后 app 接受伪造证书。

## ⚠️ 必须知道的限制

1. **Android 已把 8 张公钥全部拉黑**（`/data/misc/keychain/pubkey_blacklist.txt`），不绕黑名单会直接报 `Certificate blocklisted`；
2. **这些私钥是公开的**：任何拿到它们的人都能中间人信任该 CA 的设备。只用于自有测试机，测完取消勾选；
3. 只处理 Java 层的 `Socket.connect`，走原生网络栈的 app（cronet/QUIC、HTTP/3、非 443 端口）不会被拦截；
4. 只支持 HTTP/1.1：服务端不协商 ALPN，客户端会自然回退；
5. 客户端**完全不发 SNI** 时靠最近一次 `SSLSocketFactory.createSocket` 的 hostname 兜底，并发多个域名时可能签错；
6. 模块启用后**必须强制停止目标 app 再重开**，否则 hook 不生效。

## 构建

推送到 `main` 后 GitHub Actions 自动出 APK（`eta-cert-lab-apk` 产物）。
