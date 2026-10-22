package dev.eta.certlab;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
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
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
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
 *  - per-app CA injection (own demo CA), used as a fallback trust anchor
 *  - bypass of Conscrypt's public-key blocklist
 *  - in-process MITM that signs leaves with a leaked eMudhra intermediate
 *
 * For security research on your own device only.
 */
public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "EtaCertLab";
    private static final String CA_ASSET = "ca.pem";
    static final String EMU_DIR = "emudhra";
    /** which leaked intermediate signs the MITM leaves */
    static final String SIGNER_NAME = "EM-OV-TLS-CA-G3C";
    /** the cross-signed root that chains the intermediate to a trust anchor */
    static final String CROSS_NAME = "emSign-Root-TLS-CA-G3";

    /**
     * Leaked eMudhra intermediates: name -> private key d (a tiny integer).
     * The public keys in the certificates match d * G on P-384.
     */
    static final Map<String, Integer> EMUDHRA_KEYS = new TreeMap<String, Integer>() {{
        put("EM-DV-TLS-CA-G3B", 156);
        put("EM-DV-TLS-CA-G3C", 230);
        put("EM-EV-TLS-CA-G3B", 115);
        put("EM-EV-TLS-CA-G3C", 56);
        put("EM-OV-CS-CA-G3B", 66);
        put("EM-OV-CS-CA-G3C", 237);
        put("EM-OV-TLS-CA-G3B", 155);
        put("EM-OV-TLS-CA-G3C", 4);
    }};

    /**
     * Lazily created BouncyCastle instance. It is deliberately not a static final field:
     * constructing it registers hundreds of algorithms and would block whichever thread
     * first touches this class -- usually the app's main thread during startup.
     */
    private static volatile BouncyCastleProvider bc;

    static BouncyCastleProvider bc() {
        BouncyCastleProvider b = bc;
        if (b == null) {
            synchronized (MainHook.class) {
                b = bc;
                if (b == null) {
                    b = new BouncyCastleProvider();
                    bc = b;
                }
            }
        }
        return b;
    }

    private static final java.security.SecureRandom RNG = new java.security.SecureRandom();

    private static boolean injectCa = false;
    private static boolean bypassBlocklist = true;
    /** write a demo leaf for the configured host into the app's private dir */
    private static boolean signLeaf = true;
    static final String DEFAULT_TARGET = "integrity.1nikolas.dev";
    /** hostname to sign for; overridden by files/eta-cert-lab/target.txt */
    private static String targetHost = DEFAULT_TARGET;

    private static X509Certificate caCert;
    private static volatile boolean caLoaded;

    private static int signAttempts;
    private static boolean signDone;
    private static boolean bindHooked;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (lpparam == null || lpparam.packageName == null) return;
        if (lpparam.packageName.equals("dev.eta.certlab")) return;

        try {
            if (bypassBlocklist) hookBlocklist(lpparam);
            if (injectCa) hookSslContext(lpparam);
            // Install the network hooks immediately: they stay inert until the MITM server
            // is up, and installing them this early means Application.onCreate()
            // connections are covered as soon as it binds.
            hookInetLookup();
            hookSocketRedirect();
            // Context is almost never ready this early, so the bind hook is what really
            // does the work: it runs once the Application object exists.
            hookBind(lpparam);
            signLeafOnce();
            XposedBridge.log(TAG + ": loaded in " + lpparam.packageName);
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": hook failed in " + lpparam.packageName + ": " + t);
        }
    }

    // ------------------------------------------------------------------ bind

    /**
     * LSPosed hands us handleLoadPackage from inside ActivityThread.handleBindApplication,
     * so hooking that method here is too late: the hook point at its entry has already
     * been passed and the after-callback never fires. Hook something that is still ahead
     * of us instead -- Instrumentation.callApplicationOnCreate runs after the Application
     * object exists, and performLaunchActivity is a second chance when an app has no
     * Application subclass at all.
     */
    private static void hookBind(XC_LoadPackage.LoadPackageParam lpparam) {
        if (bindHooked) return;
        bindHooked = true;
        try {
            XposedHelpers.findAndHookMethod("android.app.Instrumentation",
                    lpparam.classLoader, "callApplicationOnCreate",
                    android.app.Application.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            boot(lpparam);
                        }
                    });
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": callApplicationOnCreate hook failed: " + t);
        }
        try {
            XposedHelpers.findAndHookMethod("android.app.ActivityThread",
                    lpparam.classLoader, "performLaunchActivity",
                    "android.app.ActivityThread$ActivityClientRecord",
                    android.content.Intent.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            boot(lpparam);
                        }
                    });
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": performLaunchActivity hook failed: " + t);
        }
    }

    private static boolean booted;

    /** Context is available now; everything slow runs off the main thread. */
    private static void boot(XC_LoadPackage.LoadPackageParam lpparam) {
        if (booted) return;
        booted = true;
        XposedBridge.log(TAG + ": booting (context ready)");
        Thread t = new Thread(() -> {
            try {
                signLeafOnce();
            } catch (Throwable e) {
                XposedBridge.log(TAG + ": signing failed: " + e);
            }
            try {
                startMitm(lpparam);
            } catch (Throwable e) {
                XposedBridge.log(TAG + ": mitm start threw: " + e);
            }
        }, "eta-certlab-init");
        t.setDaemon(true);
        t.start();
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
                mitmStarted = false;
                return;
            }
            MitmServer.start(ctx, s -> XposedBridge.log(TAG + ": " + s));
            XposedBridge.log(TAG + ": mitm port " + MitmServer.port());
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": mitm start failed: " + t);
        }
    }

    private static boolean redirectHooked;

    private static void hookSocketRedirect() {
        if (redirectHooked) return;
        redirectHooked = true;
        try {
            XposedBridge.hookAllMethods(java.net.Socket.class, "connect", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (MitmServer.BYPASS.get()) return;
                    int lp = MitmServer.port();
                    if (lp <= 0) return;
                    if (param.args == null || param.args.length == 0) return;
                    Object a = param.args[0];
                    if (!(a instanceof java.net.InetSocketAddress)) return;
                    java.net.InetSocketAddress addr = (java.net.InetSocketAddress) a;
                    if (addr.getPort() != 443) return;
                    // never redirect our own connections or connections that already point here
                    String h = addr.getAddress() == null ? null : addr.getAddress().getHostAddress();
                    if (h != null && (h.equals("127.0.0.1") || h.equals("::1"))) return;
                    if (!MitmServer.shouldIntercept(addr)) return;
                    MitmServer.noteHostForAddress(addr);
                    param.args[0] = new java.net.InetSocketAddress("127.0.0.1", lp);
                }
            });
            XposedBridge.log(TAG + ": socket redirect installed");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": socket redirect failed: " + t);
        }
    }

    /**
     * Socket.connect() only sees the resolved address (often a Clash fake-IP), so the
     * SNI fallback needs a better source: the hostname handed to SSLSocketFactory.
     */
    /**
     * OkHttp resolves names through InetAddress.getAllByName, which is the last place
     * that still knows the real hostname once Clash has handed back a fake-IP.
     */
    private static boolean inetHooked;

    private static void hookInetLookup() {
        if (inetHooked) return;
        inetHooked = true;
        try {
            XposedBridge.hookAllMethods(java.net.InetAddress.class, "getAllByName", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (param.args == null || param.args.length < 1) return;
                    Object h = param.args[0];
                    Object r = param.getResult();
                    if (h instanceof String && r instanceof java.net.InetAddress[]) {
                        MitmServer.noteHosts((java.net.InetAddress[]) r, (String) h);
                    }
                }
            });
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": inet lookup hook failed: " + t);
        }
    }

    // ------------------------------------------------------------- signing

    /** Derive the P-384 private key for a tiny integer d. */
    static PrivateKey deriveKey(int d) throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp384r1"));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(new ECPrivateKeySpec(BigInteger.valueOf(d), spec));
    }

    /** Load an intermediate certificate from assets/emudhra/<name>.crt.pem */
    static X509Certificate loadIntermediate(AssetManager am, String name) throws Exception {
        InputStream in = am.open(EMU_DIR + "/" + name + ".crt.pem");
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(readAll(in)));
        } finally {
            in.close();
        }
    }

    static X509Certificate buildLeaf(String host, java.security.PublicKey subjectKey,
                                     byte[] issuerDn, PrivateKey signer) throws Exception {
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                X500Name.getInstance(issuerDn),
                new BigInteger(64, RNG),
                new Date(now - 3600_000L),
                new Date(now + 30L * 24 * 3600 * 1000),
                new X500Name("CN=" + host),
                subjectKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName[]{new GeneralName(GeneralName.dNSName, host)}));
        builder.addExtension(Extension.keyUsage, true,
                new org.bouncycastle.asn1.x509.KeyUsage(
                        org.bouncycastle.asn1.x509.KeyUsage.digitalSignature
                                | org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment));
        // The eMudhra intermediates carry an EKU extension, so RFC 5280 requires the leaf
        // to repeat serverAuth or path validation fails.
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        X509CertificateHolder holder = builder.build(
                new JcaContentSignerBuilder("SHA384withECDSA").setProvider(bc()).build(signer));
        return new JcaX509CertificateConverter().setProvider(bc()).getCertificate(holder);
    }

    static byte[] toPem(Object o) throws Exception {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pw = new JcaPEMWriter(sw);
        pw.writeObject(o);
        pw.close();
        return sw.toString().getBytes("UTF-8");
    }

    private static synchronized void signLeafOnce() {
        if (signDone) return;
        Context ctx = appContext();
        if (ctx == null) {
            if (signAttempts < 5) {
                signAttempts++;
                XposedBridge.log(TAG + ": no app context yet, signing deferred");
            }
            return;
        }
        try {
            File dir = new File(ctx.getFilesDir(), "eta-cert-lab");
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();

            String host = targetHost;
            File hostFile = new File(dir, "target.txt");
            if (hostFile.exists()) {
                try (java.io.BufferedReader r = new java.io.BufferedReader(
                        new java.io.InputStreamReader(new FileInputStream(hostFile), "UTF-8"))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        line = line.trim();
                        if (line.isEmpty() || line.startsWith("#")) continue;
                        if (line.equals("*") || line.startsWith("*.")) continue;
                        host = line;
                        break;
                    }
                }
            }

            X509Certificate intermediate = loadIntermediate(ctx.getAssets(), SIGNER_NAME);
            Integer d = EMUDHRA_KEYS.get(SIGNER_NAME);
            if (d == null) throw new IllegalStateException("no leaked key for " + SIGNER_NAME);
            PrivateKey caKey = deriveKey(d);

            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp384r1"));
            java.security.KeyPair leafKp = kpg.generateKeyPair();

            X509Certificate leaf = buildLeaf(host, leafKp.getPublic(),
                    intermediate.getSubjectX500Principal().getEncoded(), caKey);

            writeFile(new File(dir, "leaf.pem"), toPem(leaf));
            writeFile(new File(dir, "leaf.key"), toPem(leafKp.getPrivate()));
            writeFile(new File(dir, "intermediate.pem"), toPem(intermediate));

            signDone = true;
            XposedBridge.log(TAG + ": signed leaf for " + host + " with " + SIGNER_NAME
                    + " -> " + dir.getAbsolutePath());
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
        Class<?> cls = null;
        String name = "com.android.org.conscrypt.CertBlocklistImpl";
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
            XposedBridge.log(TAG + ": CertBlocklistImpl not found");
            return;
        }
        try {
            final Class<?> target = cls;
            XposedBridge.hookAllMethods(target, "isPublicKeyBlockListed", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.setResult(Boolean.FALSE);
                }
            });
            XposedBridge.hookAllMethods(target, "isSerialNumberBlockListed", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.setResult(Boolean.FALSE);
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
            protected void beforeHookedMethod(MethodHookParam param) {
                // Must be "before": init() copies the trust managers into the SSLContextSpi,
                // so mutating the array afterwards has no effect.
                try {
                    Object[] args = param.args;
                    if (args == null) return;
                    for (int i = 0; i < args.length; i++) {
                        if (args[i] instanceof TrustManager[]) {
                            args[i] = wrap((TrustManager[]) args[i]);
                        }
                    }
                } catch (Throwable t) {
                    XposedBridge.log(TAG + ": wrap failed: " + t);
                }
            }
        });
    }

    private TrustManager[] wrap(TrustManager[] original) {
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

    static Context appContext() {
        try {
            Object app = XposedHelpers.callStaticMethod(Class.forName("android.app.ActivityThread"), "currentApplication");
            return (Context) app;
        } catch (Throwable t) {
            return null;
        }
    }

    private static synchronized X509Certificate loadCa() {
        if (caLoaded) return caCert;
        try {
            Context ctx = appContext();
            if (ctx == null) return null;
            // prefer a CA generated/placed in the app's private dir
            File f = new File(ctx.getFilesDir(), "eta-cert-lab/ca.pem");
            InputStream in;
            if (f.exists()) {
                in = new FileInputStream(f);
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
            caLoaded = true;
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": no usable demo CA (" + t + ")");
            caCert = null;
            caLoaded = false; // retry on the next handshake
        }
        return caCert;
    }

    static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }
}
