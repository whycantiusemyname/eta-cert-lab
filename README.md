# Eta Cert Lab (LSPosed)

按**应用作用域**生效的 TLS 中间人实验套件。只对你在 LSPosed 里勾选的 app 生效。

```
app ──TLS──> 本地代理 ──TLS──> 真实服务器
              │
              └─ 读 SNI → 现签证书 → 返回伪造响应
```

| 组件 | 作用 |
|---|---|
| **LSPosed 模块** | 让 app 信任我们的 CA + 绕过系统公钥黑名单 |
| **代理** `proxy/eta_mitm.py` | 按 SNI 动态签证书、按特征伪造响应、其余转发 |
| **脚本** `tools/mitm.sh` | 起代理 + 加 iptables 规则 + 退出时自动清理 |

## 为什么需要证书

app 会验证 `服务器证书` 是否链到系统信任库。三种情况实测结果：

| 出示的证书 | app 反应 |
|---|---|
| 自签测试 CA | `certificate_unknown`（链不认识） |
| eMudhra 泄漏链 | `Certificate blocklisted by public key`（链认了，被黑名单拦） |
| eMudhra 链 + 模块绕黑名单 | 握手成功，接受伪造响应 |

所以证书的作用是：**让 app 相信"我还在跟真后端说话"**。没有它，中间人连握手都过不去。

## 快速开始

```sh
# 1. 起代理 + 重定向（只针对目标 app 的 uid）
tools/mitm.sh samples/demo-ca.pem samples/demo-ca.key 8443 10495

# 2. 在 LSPosed 里启用模块、勾选目标 app、强制停止后重开

# 3. 触发 app 的完整性检查，代理日志会显示
#    [proxy] signed <host>
#    [proxy] FORGE <host> GET /api/check?token=eyJ...
```

Ctrl-C 停止：iptables 规则和代理会一起清理。

## 模块做什么

1. **注入 CA**：hook `SSLContext.init`，把 `X509TrustManager` 包一层——先走原生校验，失败再用注入的 CA 做 PKIX 校验；
2. **绕过黑名单**：hook `com.android.org.conscrypt.CertBlocklistImpl#isPublicKeyBlockListed` / `#isSerialNumberBlockListed`，返回 false；
3. **本地签证书**（可选）：内置 8 张 eMudhra 泄漏中间 CA 的弱私钥（`d` 值），运行时推导私钥并给指定域名签叶子证书，写到目标 app 的 `files/eta-cert-lab/`。

### 内置的 eMudhra 弱私钥

```
EM-DV-TLS-CA-G3B=156  EM-DV-TLS-CA-G3C=230
EM-EV-TLS-CA-G3B=115  EM-EV-TLS-CA-G3C=56
EM-OV-CS-CA-G3B=66    EM-OV-CS-CA-G3C=237
EM-OV-TLS-CA-G3B=155  EM-OV-TLS-CA-G3C=4
```

`app/src/main/assets/emudhra/` 里是这 8 张中间 CA 的**公开证书**（36 KB），用于组链。

## 代理怎么"自动识别"目标请求

| 特征 | 判断依据 |
|---|---|
| 请求带 JWE token | URL 里出现 `token=eyJ` |
| 路径像校验接口 | 路径含 `/api/check` |
| 响应含判定字段 | JSON 里有 `deviceRecognitionVerdict` |

命中任一 → 返回伪造的"全绿"JSON；否则 → 转发到真实服务器（可配 `--upstream 127.0.0.1:7890` 走 Clash）。

## ⚠️ 必须知道的限制

1. **Android 已把 8 张公钥全部拉黑**（`/data/misc/keychain/pubkey_blacklist.txt`），不绕黑名单会直接报 `Certificate blocklisted`；
2. **这些私钥是公开的**：任何拿到它们的人都能中间人信任该 CA 的设备。只用于自有测试机，测完取消勾选；
3. 代理只处理 HTTP/1.1，不支持 ECH；
4. 模块启用后**必须强制停止目标 app 再重开**，否则 hook 不生效。

## 构建

推送到 `main` 后 GitHub Actions 自动出 APK（`eta-cert-lab-apk` 产物）。
