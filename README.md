# Eta Cert Lab (LSPosed)

按**应用作用域**生效的 TLS 研究模块：只对你在 LSPosed 里勾选的 app 生效，其它 app 完全不受影响。

| 功能 | 说明 |
|---|---|
| **注入 CA** | 在目标 app 的 `SSLContext` 里叠加一个信任锚（系统 CA + 你的 CA），不修改任何系统文件 |
| **绕过公钥黑名单** | 让 `CertBlocklistImpl.isPublicKeyBlockListed()` 在目标 app 内恒返回 false，用于观察"纯信任链"行为 |

## 快速开始

1. 安装 APK（Actions 产物或自行构建）；
2. 打开 LSPosed → 模块 → 启用 **Eta Cert Lab**；
3. 在"作用域"里勾选目标 app；
4. **强制停止目标 app 再重新打开**（LSPosed 只在 app 新进程启动时注入，这步不做会以为"没生效"）；
5. LSPosed 日志里应出现：
   ```
   EtaCertLab: loaded in <package>
   ```

## 关于 CA

`app/src/main/assets/ca.pem` 里预置了一张**示例 CA**（`Eta Cert Lab Demo CA`），对应私钥在 `samples/demo-ca.key`。

- 只想用"绕过黑名单"：不用管 CA，模块加载失败也只记一条日志，不影响黑名单 hook；
- 想验证"注入 CA"：把 `assets/ca.pem` 换成**你自己的 CA 公钥**再重新构建，或直接用 `samples/demo-ca.key` 在本地签证书。

> ⚠️ **示例私钥是公开的**：任何拿到它的人都能给装了该 CA 的设备做中间人。它只用于本地实验，绝不要在你重视的设备上长期启用，测完就取消勾选。

## 本地用示例 CA 起测试服务

```sh
# 用示例 CA 签一张测试证书
openssl req -new -key leaf.key -out leaf.csr -subj "/CN=example.test"
openssl x509 -req -in leaf.csr -CA samples/demo-ca.pem -CAkey samples/demo-ca.key \
  -CAcreateserial -days 30 -sha256 -out leaf.pem

# 起服务（或直接用 mitmproxy 导入 demo-ca.key）
openssl s_server -accept 443 -cert leaf.pem -key leaf.key -www
```

## 实现要点

- hook `javax.net.ssl.SSLContext.init`：把传入的 `X509TrustManager` 包一层，先走原生校验，失败时再用注入的 CA 做 PKIX 校验；
- hook `com.android.org.conscrypt.CertBlocklistImpl#isPublicKeyBlockListed` / `#isSerialNumberBlockListed`：直接返回 false；
- 兼容 LSPosed 的经典 Xposed API（`de.robv.android.xposed:api:82`）；如需迁移到 `io.github.libxposed:api` 可自行替换。

## 注意

- 仅用于**自有设备**的安全研究；
- 注入 CA 会降低目标 app 的 TLS 强度：持有该 CA 私钥的人可以中间人它的流量；
- 绕过黑名单意味着**已知被攻陷的证书也会被接受**——这正是实验目的，测完请取消勾选。
