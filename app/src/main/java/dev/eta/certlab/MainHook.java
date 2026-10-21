package dev.eta.certlab;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Eta Cert Lab (LSPosed)
 *
 * Scope: only apps selected in LSPosed manager.
 *  - per-app CA injection (own demo CA or a derived eMudhra intermediate)
 *  - optional bypass of Conscrypt's public-key blocklist
 *  - optional on-device leaf signing with the leaked eMudhra intermediates
 *
 * For security research on your own device only.
 */
public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "EtaCertLab";
    private static final String CA_ASSET = "ca.pem";
    private static final String EMU_DIR = "emudhra";

    /**
     * Leaked eMudhra intermediates: name -> private key d (a tiny integer).
     * The public keys in the certificates match d * G on P-384.
     */
    private static final Map<String, Integer> EMUDHRA_KEYS = new TreeMap<String, Integer>() {{
        put("EM-DV-TLS-CA-G3B", 156);
        put("EM-DV-TLS-CA-G3C", 230);
        put("EM-EV-TLS-CA-G3B", 115);
        put("EM-EV-TLS-CA-G3C", 56);
        put("EM-OV-CS-CA-G3B", 66);
        put("EM-OV-CS-CA-G3C", 237);
        put("EM-OV-TLS-CA-G3B", 155);
        put("EM-OV-TLS-CA-G3C", 4);
    }};

    private static boolean injectCa = true;
    private static boolean bypassBlocklist = true;
    /** sign a leaf certificate on device with the leaked intermediate */
    private static boolean signLeaf = true;
    /** hostname to sign for; overridden by files/eta-cert-lab/target.txt */
    private static String targetHost = "integrity.1nikolas.dev";
    /** which intermediate to use for signing */
    private static String signerName = "EM-OV-TLS-CA-G3C";

    private static X509Certificate caCert;
    private static boolean caLoaded;
    private static boolean signDone;
    private static volatile boolean signOk;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (lpparam == null || lpparam.packageName == null) return;
        if (lpparam.packageName.equals("dev.eta.certlab")) return;

        try {
            if (bypassBlocklist) hookBlocklist(lpparam);
            if (injectCa) hookSslContext(lpparam);
            if (signLeaf) {
                // Context is usually not ready this early: retry once the app is bound.
                signLeafOnce(lpparam);
                if (!signOk) {
                    try {
                        XposedHelpers.findAndHookMethod("android.app.ActivityThread",
                                lpparam.classLoader, "handleBindApplication",
                                "android.app.ActivityThread$AppBindData",
                                new XC_MethodHook() {
                                    @Override
                                    protected void afterHookedMethod(MethodHookParam param) {
                                        signLeafOnce(lpparam);
                                        startMitm(lpparam);
                                    }
                                });
                    } catch (Throwable t) {
                        XposedBridge.log(TAG + ": bind hook failed: " + t);
                    }
                }
            }
            XposedBridge.log(TAG + ": loaded in " + lpparam.packageName);
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": hook failed in " + lpparam.packageName + ": " + t);
        }
    }


    // ------------------------------------------------------------------ mitm

    private static boolean mitmStarted;

    private static void startMitm(XC_LoadPackage.LoadPackageParam lpparam) {
        if (mitmStarted) return;
        mitmStarted = true;
        try {
            Context ctx = appContext();
            if (ctx == null) {
                XposedBridge.log(TAG + ": no context, mitm not started");
                return;
            }
            MitmServer.start(ctx, s -> XposedBridge.log(TAG + ": " + s));
            hookSocketRedirect(lpparam);
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": mitm start failed: " + t);
        }
    }

    private static void hookSocketRedirect(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedBridge.hookAllMethods(java.net.Socket.class, "connect", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (MitmServer.BYPASS.get()) return;
                    int port = MitmServer.port();
                    if (port <= 0) return;
                    Object a = param.args[0];
                    if (!(a instanceof java.net.InetSocketAddress)) return;
                    java.net.InetSocketAddress addr = (java.net.InetSocketAddress) a;
                    if (addr.getPort() != 443) return;
                    param.args[0] = new java.net.InetSocketAddress("127.0.0.1", port);
                }
            });
            XposedBridge.log(TAG + ": socket redirect installed");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": socket redirect failed: " + t);
        }
    }

    // ------------------------------------------------------------- signing


    /** Derive the P-384 private key for a tiny integer d. */
    private static PrivateKey deriveKey(int d) throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp384r1"));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(new ECPrivateKeySpec(BigInteger.valueOf(d), spec));
    }

    /** Load an intermediate certificate from assets/emudhra/<name>.crt.pem */
    private static X509Certificate loadIntermediate(AssetManager am, String name) throws Exception {
        InputStream in = am.open(EMU_DIR + "/" + name + ".crt.pem");
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(readAll(in)));
        } finally {
            in.close();
        }
    }

    private static String toPem(Object o) throws Exception {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pw = new JcaPEMWriter(sw);
        pw.writeObject(o);
        pw.close();
        return sw.toString();
    }

    private void signLeafOnce(XC_LoadPackage.LoadPackageParam lpparam) {
        synchronized (MainHook.class) {
            if (signDone) return;
            signDone = true;
        }
        try {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            Context ctx = appContext();
            if (ctx == null) {
                XposedBridge.log(TAG + ": no app context, skip signing");
                return;
            }
            File dir = new File(ctx.getFilesDir(), "eta-cert-lab");
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();

            String host = targetHost;
            File hostFile = new File(dir, "target.txt");
            if (hostFile.exists()) {
                String s = new String(readAll(new java.io.FileInputStream(hostFile)), "UTF-8").trim();
                if (s.length() > 0) host = s;
            }

            X509Certificate intermediate = loadIntermediate(ctx.getAssets(), signerName);
            PrivateKey caKey = deriveKey(EMUDHRA_KEYS.get(signerName));

            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp384r1"));
            java.security.KeyPair leafKp = kpg.generateKeyPair();

            long now = System.currentTimeMillis();
            X500Name issuer = new X500Name(intermediate.getSubjectX500Principal().getName());
            X500Name subject = new X500Name("CN=" + host);
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuer,
                    BigInteger.valueOf(now),
                    new Date(now - 3600_000L),
                    new Date(now + 30L * 24 * 3600 * 1000),
                    subject,
                    leafKp.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName[]{new GeneralName(GeneralName.dNSName, host)}));

            X509CertificateHolder holder = builder.build(
                    new JcaContentSignerBuilder("SHA384withECDSA").build(caKey));
            X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(holder);

            writeFile(new File(dir, "leaf.pem"), toPem(leaf).getBytes("UTF-8"));
            writeFile(new File(dir, "leaf.key"), toPem(leafKp.getPrivate()).getBytes("UTF-8"));
            writeFile(new File(dir, "intermediate.pem"), toPem(intermediate).getBytes("UTF-8"));

            signOk = true;
            XposedBridge.log(TAG + ": signed leaf for " + host + " with " + signerName + " -> " + dir.getAbsolutePath());
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": signing failed: " + t);
        }
    }

    private static void writeFile(File f, byte[] data) throws Exception {
        FileOutputStream fos = new FileOutputStream(f);
        try {
            fos.write(data);
        } finally {
            fos.close();
        }
        //noinspection ResultOfMethodCallIgnored
        f.setReadable(true, false);
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
            XposedBridge.log(TAG + ": blocklist hook failed: " + t);
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
                            args[i] = wrap((TrustManager[]) args[i], lpparam);
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
                out.add(new CaTrustManager((X509TrustManager) tm));
            } else {
                out.add(tm);
            }
        }
        return out.toArray(new TrustManager[0]);
    }

    // --------------------------------------------------------------- trust mgr

    private static class CaTrustManager implements X509TrustManager {
        private final X509TrustManager delegate;

        CaTrustManager(X509TrustManager delegate) {
            this.delegate = delegate;
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

    private static Context appContext() {
        try {
            Object app = XposedHelpers.callStaticMethod(Class.forName("android.app.ActivityThread"), "currentApplication");
            return (Context) app;
        } catch (Throwable t) {
            return null;
        }
    }

    private static synchronized X509Certificate loadCa() {
        if (caLoaded) return caCert;
        caLoaded = true;
        try {
            Context ctx = appContext();
            if (ctx == null) return null;
            // prefer a CA generated/placed in the app's private dir
            File f = new File(ctx.getFilesDir(), "eta-cert-lab/ca.pem");
            InputStream in;
            if (f.exists()) {
                in = new java.io.FileInputStream(f);
            } else {
                in = ctx.getAssets().open(CA_ASSET);
            }
            try {
                byte[] buf = readAll(in);
                caCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(buf));
            } finally {
                in.close();
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": no usable CA (" + t + ")");
            caCert = null;
        }
        return caCert;
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }
}
