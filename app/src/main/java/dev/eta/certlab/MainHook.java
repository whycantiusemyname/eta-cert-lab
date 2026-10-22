package dev.eta.certlab;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Eta Cert Lab (LSPosed)
 *
 * One job only: stop Conscrypt from rejecting the intercepted certificates because
 * their public keys appear in the system blocklist.
 *
 * Everything else lives outside the module:
 *
 *   iptables -t nat -I OUTPUT 1 -p tcp --dport 443 \
 *       -m owner --uid-owner <uid> -j REDIRECT --to-ports 18080
 *   mitmdump --mode transparent --listen-port 18080 --set confdir=<dir with eMudhra CA>
 *
 * mitmproxy signs a leaf per SNI with the leaked eMudhra intermediate and sends the
 * full chain (leaf, EM OV TLS CA - G3C, emSign Root TLS CA - G3), so the client
 * validates it against the stock trust store. No CA is installed anywhere, no app or
 * hostname is hard-coded, and the only per-app decision is the uid in iptables.
 *
 * For security research on your own device only.
 */
public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "EtaCertLab";
    private static final String MODULE_PKG = "dev.eta.certlab";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (lpparam == null || lpparam.packageName == null) return;
        if (lpparam.packageName.equals(MODULE_PKG)) return;

        try {
            int n = hookBlocklist(lpparam);
            XposedBridge.log(TAG + ": blocklist bypass armed in " + lpparam.packageName
                    + " (" + n + " method(s))");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": hook failed in " + lpparam.packageName + ": " + t);
        }
    }

    private int hookBlocklist(XC_LoadPackage.LoadPackageParam lpparam) {
        String name = "com.android.org.conscrypt.CertBlocklistImpl";
        Class<?> cls = null;
        ClassLoader[] loaders = new ClassLoader[]{
                lpparam.classLoader, MainHook.class.getClassLoader(), null};
        for (ClassLoader cl : loaders) {
            try {
                cls = cl == null ? Class.forName(name) : XposedHelpers.findClass(name, cl);
                if (cls != null) break;
            } catch (Throwable ignored) {
            }
        }
        if (cls == null) {
            XposedBridge.log(TAG + ": CertBlocklistImpl not found, nothing hooked");
            return 0;
        }

        final int[] count = {0};
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                param.setResult(Boolean.FALSE);
            }
        };
        XposedBridge.hookAllMethods(cls, "isPublicKeyBlockListed", hook);
        XposedBridge.hookAllMethods(cls, "isSerialNumberBlockListed", hook);
        count[0] = 2;
        return count[0];
    }
}
