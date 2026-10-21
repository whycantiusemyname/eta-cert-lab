package dev.eta.certlab;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * In-process MITM server.
 *
 * Lives inside the target app: the module redirects the app's TCP connections here,
 * this server reads the SNI from the ClientHello, signs a matching certificate with
 * the bundled CA, terminates TLS, and either fakes the response or forwards upstream.
 */
final class MitmServer {

    interface Logger {
        void log(String s);
    }

    private static final String TAG = "EtaCertLab";

    /** thread-local flag so our own upstream connections are not redirected again */
    static final ThreadLocal<Boolean> BYPASS = new ThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return Boolean.FALSE;
        }
    };

    private static volatile int port = -1;
    private static final Map<String, Object[]> certCache = new HashMap<>();
    private static X509Certificate caCert;
    private static PrivateKey caKey;
    private static Logger logger;

    static int port() {
        return port;
    }

    static synchronized void start(Context ctx, Logger l) {
        if (port > 0) return;
        logger = l;
        try {
            loadCa(ctx);
            ServerSocket ss = new ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress("127.0.0.1", 0));
            port = ss.getLocalPort();
            log("mitm server on 127.0.0.1:" + port);
            Thread t = new Thread(() -> {
                while (true) {
                    try {
                        final Socket c = ss.accept();
                        new Thread(() -> handle(c)).start();
                    } catch (Throwable e) {
                        log("accept failed: " + e);
                    }
                }
            }, "eta-mitm-accept");
            t.setDaemon(true);
            t.start();
        } catch (Throwable e) {
            log("mitm start failed: " + e);
        }
    }

    // ------------------------------------------------------------- CA / certs

    private static void loadCa(Context ctx) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        AssetManager am = ctx.getAssets();
        InputStream cin = am.open("ca.pem");
        caCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(readAll(cin)));
        cin.close();

        // key may live in the app's private dir (exported by the module) or in assets
        File kf = new File(ctx.getFilesDir(), "eta-cert-lab/ca.key");
        InputStream kin = kf.exists() ? new FileInputStream(kf) : am.open("ca.key");
        byte[] kb = readAll(kin);
        kin.close();
        caKey = (PrivateKey) new org.bouncycastle.openssl.PEMParser(
                new java.io.InputStreamReader(new ByteArrayInputStream(kb))).readObject();
        if (caKey == null) throw new IllegalStateException("ca.key unreadable");
    }

    private static synchronized Object[] certFor(String sni) throws Exception {
        Object[] cached = certCache.get(sni);
        if (cached != null) return cached;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        long now = System.currentTimeMillis();
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(now), new Date(now - 3600_000L),
                new Date(now + 30L * 24 * 3600 * 1000), new X500Name("CN=" + sni), kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName[]{new GeneralName(GeneralName.dNSName, sni)}));
        X509CertificateHolder h = b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKey));
        X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(h);

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setKeyEntry("leaf", kp.getPrivate(), new char[0], new java.security.cert.Certificate[]{leaf});
        Object[] out = new Object[]{ks, kp.getPrivate()};
        certCache.put(sni, out);
        log("signed " + sni);
        return out;
    }

    // ------------------------------------------------------------------ serve

    private static void handle(Socket c) {
        try {
            c.setSoTimeout(15000);
            String sni = readSni(c);
            if (sni == null) {
                c.close();
                return;
            }
            Object[] material = certFor(sni);
            KeyStore ks = (KeyStore) material[0];
            char[] pw = new char[0];

            SSLContext ctx = SSLContext.getInstance("TLS");
            javax.net.ssl.KeyManagerFactory kmf =
                    javax.net.ssl.KeyManagerFactory.getInstance("PKIX");
            kmf.init(ks, pw);
            ctx.init(kmf.getKeyManagers(), null, null);
            SSLSocket tls = (SSLSocket) ctx.getSocketFactory()
                    .createSocket(c, sni, 443, true);
            tls.startHandshake();

            byte[] req = readHttpRequest(tls.getInputStream());
            if (req == null) {
                tls.close();
                return;
            }
            String head = new String(req);
            if (looksLikeIntegrity(head)) {
                log("FORGE " + sni);
                tls.getOutputStream().write(fakeResponse());
            } else {
                log("PASS  " + sni);
                byte[] resp = forward(sni, req);
                tls.getOutputStream().write(resp == null ? badGateway() : resp);
            }
            tls.getOutputStream().flush();
            tls.close();
        } catch (Throwable e) {
            log("handle error: " + e);
            try {
                c.close();
            } catch (Throwable ignored) {
            }
        }
    }

    // --------------------------------------------------------------- helpers

    static String readSni(Socket s) {
        try {
            byte[] peeked = new byte[16384];
            int n = s.getInputStream().read(peeked);
            if (n < 5 || peeked[0] != 0x16) return null;
            int len = ((peeked[3] & 0xff) << 8) | (peeked[4] & 0xff);
            if (n < 5 + len || peeked[5] != 0x01) return null;
            int i = 5 + 4 + 2 + 32;
            i += 1 + (peeked[i] & 0xff);                       // session id
            int cs = ((peeked[i] & 0xff) << 8) | (peeked[i + 1] & 0xff);
            i += 2 + cs;
            i += 1 + (peeked[i] & 0xff);                       // compression
            int extLen = ((peeked[i] & 0xff) << 8) | (peeked[i + 1] & 0xff);
            i += 2;
            int end = Math.min(i + extLen, n);
            while (i + 4 <= end) {
                int type = ((peeked[i] & 0xff) << 8) | (peeked[i + 1] & 0xff);
                int elen = ((peeked[i + 2] & 0xff) << 8) | (peeked[i + 3] & 0xff);
                i += 4;
                if (type == 0) {
                    int nl = ((peeked[i + 3] & 0xff) << 8) | (peeked[i + 4] & 0xff);
                    return new String(peeked, i + 5, nl, "ASCII");
                }
                i += elen;
            }
            return null;
        } catch (Throwable e) {
            return null;
        }
    }

    private static byte[] readHttpRequest(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int state = 0;
        int b;
        while ((b = in.read()) != -1) {
            bos.write(b);
            state = (b == '\r' || b == '\n') ? state + 1 : 0;
            if (state >= 4) break;
            if (bos.size() > 65536) break;
        }
        if (bos.size() == 0) return null;
        return bos.toByteArray();
    }

    private static boolean looksLikeIntegrity(String head) {
        String h = head.toLowerCase();
        return h.contains("token=eyj") || h.contains("/api/check") || h.contains("integrity");
    }

    private static byte[] fakeResponse() {
        String body = "{\"deviceIntegrity\":{\"deviceRecognitionVerdict\":["
                + "\"MEETS_BASIC_INTEGRITY\",\"MEETS_DEVICE_INTEGRITY\",\"MEETS_STRONG_INTEGRITY\"]}}";
        byte[] b = body.getBytes();
        String head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + b.length + "\r\nConnection: close\r\n\r\n";
        byte[] h = head.getBytes();
        byte[] out = new byte[h.length + b.length];
        System.arraycopy(h, 0, out, 0, h.length);
        System.arraycopy(b, 0, out, h.length, b.length);
        return out;
    }

    private static byte[] badGateway() {
        return "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".getBytes();
    }

    /** Connect to the real server (bypassing the redirect hook) and relay one request. */
    private static byte[] forward(String sni, byte[] req) {
        BYPASS.set(Boolean.TRUE);
        try {
            Socket raw = new Socket();
            raw.connect(new InetSocketAddress(sni, 443), 10000);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, null, null);
            SSLSocket tls = (SSLSocket) ctx.getSocketFactory().createSocket(raw, sni, 443, true);
            tls.startHandshake();
            OutputStream os = tls.getOutputStream();
            os.write(req);
            os.flush();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            InputStream is = tls.getInputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
            tls.close();
            return bos.toByteArray();
        } catch (Throwable e) {
            log("forward failed " + sni + ": " + e);
            return null;
        } finally {
            BYPASS.set(Boolean.FALSE);
        }
    }

    private static void log(String s) {
        if (logger != null) logger.log(s);
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }
}
