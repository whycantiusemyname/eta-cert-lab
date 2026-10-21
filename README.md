# Eta Cert Lab (LSPosed)

按**应用作用域**生效的 TLS 研究模块：只对你在 LSPosed 里勾选的 app 生效，其它 app 完全不受影响。

| 功能 | 说明 |
|---|---|
| **注入 CA** | 在目标 app 的 `SSLContext` 里叠加一个信任锚（系统 CA + 你的 CA），不修改系统文件 |
| **绕过公钥黑名单** | 让 `CertBlocklistImpl.isPublicKeyBlockListed()` 在目标 app 内恒返回 false |
| **本地签证书** | 内置 8 张 eMudhra 泄漏中间 CA 的弱私钥（`d` 值），运行时推导私钥并为指定域名签叶子证书 |

## 快速开始

1. 安装 APK（Actions 产物或自行构建）；
2. LSPosed → 模块 → 启用 **Eta Cert Lab**；
3. 作用域里勾选目标 app；
4. **强制停止目标 app 再重开**（LSPosed 只在 app 新进程启动时注入）；
5. LSPosed 日志应出现：
   ```
   EtaCertLab: loaded in <package>
   EtaCertLab: signed leaf for <host> with EM-OV-TLS-CA-G3C -> /data/user/0/<pkg>/files/eta-cert-lab
   ```

## 本地签证书是怎么做的

模块里内置了 8 张泄漏中间 CA 的**私钥整数**（这些密钥极弱，是单个小整数）：

```
EM-DV-TLS-CA-G3B=156  EM-DV-TLS-CA-G3C=230
EM-EV-TLS-CA-G3B=115  EM-EV-TLS-CA-G3C=56
EM-OV-CS-CA-G3B=66    EM-OV-CS-CA-G3C=237
EM-OV-TLS-CA-G3B=155  EM-OV-TLS-CA-G3C=4
```

运行时流程：

1. `d` → P-384 私钥（`ECPrivateKeySpec`）；
2. 用 BouncyCastle 构造叶子证书（CN/SAN = 目标域名，签发者 = 对应中间 CA）；
3. 用该中间 CA 的私钥 `SHA384withECDSA` 签名；
4. 输出到目标 app 的私有目录 `files/eta-cert-lab/`：
   - `leaf.pem` / `leaf.key` —— 叶子证书与私钥
   - `intermediate.pem` —— 中间 CA 证书（组链必需）
5. 想要别的域名：写 `files/eta-cert-lab/target.txt`（一行一个域名）。

`app/src/main/assets/emudhra/` 里是 8 张中间 CA 的**公开证书**（36 KB），用来组链——叶子证书需要它们才能验到根。

## 用签出来的证书起服务

```sh
# 从 app 私有目录取（root）
adb shell su -c 'cat /data/user/0/<pkg>/files/eta-cert-lab/leaf.pem'
adb shell su -c 'cat /data/user/0/<pkg>/files/eta-cert-lab/leaf.key'

# 起 TLS 服务
openssl s_server -accept 443 -cert leaf.pem -key leaf.key \
  -cert_chain intermediate.pem -www
```

再把流量指到这个端口（iptables 重定向）即可。

## 关于 CA（可选功能）

`assets/ca.pem` 预置了一张**示例 CA**（`Eta Cert Lab Demo CA`），私钥在 `samples/demo-ca.key`。

- 只想用黑名单绕过：不用管 CA；
- 想验证"注入 CA"：换成你自己的 CA 公钥再构建。

> ⚠️ **示例私钥是公开的**：任何拿到它的人都能给装了该 CA 的设备做中间人。只用于本地实验。

## ⚠️ 必须知道的限制

1. **Android 已把 8 张公钥全部拉黑**（`/data/misc/keychain/pubkey_blacklist.txt`），
   不绕过黑名单会报 `Certificate blocklisted by public key`；
2. **这些私钥是公开的**：任何拿到它们的人都能中间人信任该 CA 的设备。只用于自有测试机，
   测完取消模块勾选、不要长期启用；
3. 模块只负责"信任 + 绕黑名单 + 签证书"，**不代理流量**——还需要 iptables 重定向到本地服务。

## 实现要点

- hook `javax.net.ssl.SSLContext.init`：包一层 `X509TrustManager`，先走原生校验，失败再用注入的 CA 做 PKIX 校验；
- hook `com.android.org.conscrypt.CertBlocklistImpl#isPublicKeyBlockListed` / `#isSerialNumberBlockListed`：返回 false；
- 依赖：BouncyCastle（`bcprov` + `bcpkix`）用于构造和签名 X.509。
