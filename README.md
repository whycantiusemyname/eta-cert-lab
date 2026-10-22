# Eta Cert Lab

拦截任意指定 app 的 TLS 流量，用 **2026-10 泄漏的 eMudhra 中间 CA** 给任意域名现签证书。客户端不需要安装任何 CA：整条链在 Android 自带信任库里就能验完。

```
app (uid N) ──443──> iptables REDIRECT ──> mitmproxy 127.0.0.1:18080
                                                  │
                                      按 SNI 现签 leaf（EM OV TLS CA - G3C）
                                      发 leaf + 中间 CA + 交叉证书
                                                  │
                                            ──> 真实服务器
```

## 为什么能不用装 CA

`assets/emudhra/` 里是 8 张泄漏的中间 CA 的公开证书，私钥就是单个小整数（`d`）：

```
EM-DV-TLS-CA-G3B=156  EM-DV-TLS-CA-G3C=230
EM-EV-TLS-CA-G3B=115  EM-EV-TLS-CA-G3C=56
EM-OV-CS-CA-G3B=66    EM-OV-CS-CA-G3C=237
EM-OV-TLS-CA-G3B=155  EM-OV-TLS-CA-G3C=4
```

`d=4` 推出的 P-384 私钥就是 `EM OV TLS CA - G3C` 的私钥。用它签 leaf，再把中间 CA 和交叉证书一起发出去，客户端顺着

```
leaf ← EM OV TLS CA - G3C ← emSign Root TLS CA - G3 ← emSign ECC Root CA - G3（系统根）
```

验到系统信任库里的 `emSign ECC Root CA - G3`，验证通过。

唯一的障碍是 Android 把 8 张中间 CA 的公钥拉进了黑名单（`/data/misc/keychain/pubkey_blacklist.txt`），所以模块只做一件事：让 `CertBlocklistImpl` 的两个判断返回 false。

## 没有任何东西写死

- **哪个 app**：只由 iptables 的 `--uid-owner` 决定；
- **哪些域名**：不限制。mitmproxy 的 `CertStore` 按 SNI 现签，`example.com`、`www.google.com`、`api.github.com` 各自拿到自己的证书；
- **证书**：每张 leaf 现场签，缓存按域名，私钥是 `d` 推出来的。

## 用法

```sh
# 1. 生成 mitmproxy 的 CA 文件（私钥从 d 派生）
tools/make-ca.sh 4 /data/local/tmp/mitm-emu

# 2. 起透明代理
mitmdump --mode transparent --listen-port 18080 \
    --set confdir=/data/local/tmp/mitm-emu

# 3. 只重定向目标 app 的 443
iptables -t nat -I OUTPUT 1 -p tcp --dport 443 \
    -m owner --uid-owner <uid> -j REDIRECT --to-ports 18080

# 4. LSPosed 里启用模块、勾选该 app、强制停止后重开
```

停止：

```sh
iptables -t nat -D OUTPUT -p tcp --dport 443 \
    -m owner --uid-owner <uid> -j REDIRECT --to-ports 18080
```

`mitmproxy` 的请求日志会打出每个连接的 SNI、请求行和响应码。

## 模块做什么

只有一件事：hook `com.android.org.conscrypt.CertBlocklistImpl` 的
`isPublicKeyBlockListed` / `isSerialNumberBlockListed`，返回 false。

不注入 CA、不改系统分区、不碰 app 代码。

## ⚠️ 限制

1. 这些私钥是公开的，任何拿到的人都能中间人信任该 CA 的设备。只用于自有测试机；
2. 只处理 Java 层可重定向的 TCP 连接；走原生网络栈（cronet、QUIC）的流量不经过 iptables 的这条规则；
3. 模块启用后必须**强制停止目标 app 再重开**；
4. 撤销时记得删 iptables 规则。

## 构建

推送到 `main` 后 GitHub Actions 出 APK（`eta-cert-lab-apk` 产物）。
