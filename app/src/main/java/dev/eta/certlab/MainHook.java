package dev.eta.certlab;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Eta Cert Lab (LSPosed)
 *
 * Scope: only apps selected in LSPosed manager.
 *  - adds a user-supplied CA (assets/ca.pem) on top of the system trust store
 *  - optionally bypasses Conscrypt's public-key blocklist
 *
 * For security research on your own device.
 */
public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "EtaCertLab";
    private static final String CA_ASSET = "ca.pem";

    /** set false if you only want the blocklist bypass */
    private static boolean injectCa = true;
    /** set false if you do not want to bypass the blocklist */
    private static boolean bypassBlocklist = true;

    private static X509Certificate caCert;
    private static boolean caLoaded;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (lpparam == null || lpparam.packageName == null) return;
        if (lpparam.packageName.equals("dev.eta.certlab")) return;

        try {
            if (bypassBlocklist) hookBlocklist(lpparam);
            if (injectCa) hookSslContext(lpparam);
            XposedBridge.log(TAG + ": loaded in " + lpparam.packageName);
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": hook failed in " + lpparam.packageName + ": " + t);
        }
    }

    // ---------------------------------------------------------------- blocklist

    private void hookBlocklist(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> cls = XposedHelpers.findClass("com.android.org.conscrypt.CertBlocklistImpl", lpparam.classLoader);
            XposedBridge.hookAllMethods(cls, "isPublicKeyBlockListed", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.setResult(false);
                }
            });
            XposedBridge.hookAllMethods(cls, "isSerialNumberBlockListed", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.setResult(false);
                }
            });
        } catch (Throwable t) {
            // class may not exist on older builds
        }
    }

    // ------------------------------------------------------------------- SSL

    private void hookSslContext(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.hookAllMethods(SSLContext.class, "init", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                try {
                    Object[] args = param.args;
                    if (args == null) return;
                    for (int i = 0; i < args.length; i++) {
                        if (args[i] instanceof TrustManager[]) {
                            TrustManager[] original = (TrustManager[]) args[i];
                            args[i] = wrap(original, lpparam);
                        }
                    }
                } catch (Throwable t) {
                    XposedBridge.log(TAG + ": wrap failed: " + t);
                }
            }
        });
    }

    private TrustManager[] wrap(TrustManager[] original, XC_LoadPackage.LoadPackageParam lpparam) {
        if (original == null) return null;
        List<TrustManager> out = new ArrayList<>();
        for (TrustManager tm : original) {
            if (tm instanceof X509TrustManager) {
                out.add(new CaTrustManager((X509TrustManager) tm, lpparam));
            } else {
                out.add(tm);
            }
        }
        return out.toArray(new TrustManager[0]);
    }

    // --------------------------------------------------------------- trust mgr

    private static class CaTrustManager implements X509TrustManager {
        private final X509TrustManager delegate;
        private final XC_LoadPackage.LoadPackageParam lpparam;

        CaTrustManager(X509TrustManager delegate, XC_LoadPackage.LoadPackageParam lpparam) {
            this.delegate = delegate;
            this.lpparam = lpparam;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            try {
                delegate.checkServerTrusted(chain, authType);
                return;
            } catch (java.security.cert.CertificateException original) {
                X509Certificate ca = loadCa();
                if (ca == null) throw original;
                verifyWithCa(chain, ca);
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            X509Certificate[] base = delegate.getAcceptedIssuers();
            X509Certificate ca = loadCa();
            if (ca == null) return base;
            if (base == null) return new X509Certificate[]{ca};
            X509Certificate[] merged = Arrays.copyOf(base, base.length + 1);
            merged[base.length] = ca;
            return merged;
        }

        private void verifyWithCa(X509Certificate[] chain, X509Certificate ca) throws java.security.cert.CertificateException {
            try {
                Set<TrustAnchor> anchors = new HashSet<>();
                anchors.add(new TrustAnchor(ca, null));
                PKIXParameters params = new PKIXParameters(anchors);
                params.setRevocationEnabled(false);
                CertPath cp = CertificateFactory.getInstance("X.509").generateCertPath(Arrays.asList(chain));
                CertPathValidator.getInstance("PKIX").validate(cp, params);
            } catch (Exception e) {
                throw new java.security.cert.CertificateException("EtaCertLab: not trusted by injected CA", e);
            }
        }
    }

    // ------------------------------------------------------------------- CA

    private synchronized X509Certificate loadCa() {
        if (caLoaded) return caCert;
        caLoaded = true;
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object app = XposedHelpers.callStaticMethod(at, "currentApplication");
            if (app == null) return null;
            Context ctx = (Context) app;
            AssetManager am = ctx.getAssets();
            InputStream in = am.open(CA_ASSET);
            byte[] buf = readAll(in);
            in.close();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            caCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(buf));
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": no usable " + CA_ASSET + " (" + t + ")");
            caCert = null;
        }
        return caCert;
    }

    private static byte[] readAll(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }
}
