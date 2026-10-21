# Eta Cert Lab (LSPosed)

按**应用作用域**生效的 TLS 研究模块：只对你在 LSPosed 里勾选的 app 生效，其它 app 完全不受影响。

| 功能 | 说明 |
|---|---|
| **注入 CA** | 在目标 app 的 `SSLContext` 里叠加一个信任锚（系统 CA + 你的 CA），不修改任何系统文件 |
| **绕过公钥黑名单** | 让 `CertBlocklistImpl.isPublicKeyBlockListed()` 在目标 app 内恒返回 false，用于观察"纯信任链"行为 |

## 为什么按作用域更好

- **不污染全局**：只有勾选的 app 受影响，其它 app 的 TLS 保持原样；
- **时机正确**：LSPosed 在 app 代码执行**之前**注入，不存在"信任库已缓存"的时机问题；
- **随时可关**：在 LSPosed 里取消勾选即可，无需卸载或重启系统。

## 使用

1. **准备 CA**（只用公钥部分，绝不提交私钥）：
   ```sh
   cp my-test-ca.pem app/src/main/assets/ca.pem
   ```
   如果只想用黑名单绕过，保留占位文件即可。

2. **构建 APK**：
   - GitHub Actions：推送到 `main` 后，在 Actions 页面下载 `eta-cert-lab-apk` 产物；
   - 或本地：`./gradlew assembleDebug`。

3. **安装并启用**：
   - 安装 APK；
   - 打开 LSPosed → 模块 → 启用 **Eta Cert Lab**；
   - 在"作用域"里勾选目标 app（默认给了两个 checker 的包名）；
   - 强制停止目标 app 后重新打开。

4. **验证**：
   ```sh
   # LSPosed 日志里应出现
   EtaCertLab: loaded in <package>
   ```

## 实现要点

- hook `javax.net.ssl.SSLContext.init`：把传入的 `X509TrustManager` 包一层，先走原生校验，失败时再用注入的 CA 做 PKIX 校验；
- hook `com.android.org.conscrypt.CertBlocklistImpl#isPublicKeyBlockListed` / `#isSerialNumberBlockListed`：直接返回 false。

## 注意

- 仅用于**自有设备**的安全研究；
- 注入 CA 会降低目标 app 的 TLS 强度：持有该 CA 私钥的人可以中间人它的流量；
- 绕过黑名单意味着**已知被攻陷的证书也会被接受**——这正是实验目的，测完请取消勾选。
