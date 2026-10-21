package dev.eta.certlab;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * In-process MITM server.
 *
 * The module redirects the app's TCP/443 connections here. Instead of parsing the
 * ClientHello by hand (which would consume it), we let Conscrypt do the handshake and
 * pick the certificate inside a custom KeyManager, where the SNI is already available
 * through the handshake session.
 */
final class MitmServer {

    interface Logger {
        void log(String s);
    }

    /** thread-local flag so our own upstream connections are not redirected again */
    static final ThreadLocal<Boolean> BYPASS = new ThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return Boolean.FALSE;
        }
    };

    private static volatile int port = -1;
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
                        Thread w = new Thread(() -> handle(c), "eta-mitm-conn");
                        w.setDaemon(true);
                        w.start();
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

    // ------------------------------------------------------------- CA loading

    private static void loadCa(Context ctx) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        AssetManager am = ctx.getAssets();
        InputStream cin = am.open("ca.pem");
        try {
            caCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(readAll(cin)));
        } finally {
            cin.close();
        }

        File kf = new File(ctx.getFilesDir(), "eta-cert-lab/ca.key");
        InputStream kin = kf.exists() ? new FileInputStream(kf) : am.open("ca.key");
        try {
            PEMParser parser = new PEMParser(new InputStreamReader(kin));
            Object o = parser.readObject();
            JcaPEMKeyConverter conv = new JcaPEMKeyConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (o instanceof PEMKeyPair) {
                caKey = conv.getKeyPair((PEMKeyPair) o).getPrivate();
            } else if (o instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                caKey = conv.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) o);
            } else {
                throw new IllegalStateException("unsupported key format: " + o);
            }
        } finally {
            kin.close();
        }
    }

    // ------------------------------------------------------- per-SNI signing

    private static final Map<String, Object[]> CACHE = new HashMap<>();

    /** Returns {PrivateKey, X509Certificate[]} for the given host. */
    private static synchronized Object[] materialFor(String host) throws Exception {
        Object[] cached = CACHE.get(host);
        if (cached != null) return cached;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        long now = System.currentTimeMillis();
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(now),
                new Date(now - 3600_000L), new Date(now + 30L * 24 * 3600 * 1000),
                new X500Name("CN=" + host), kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName[]{new GeneralName(GeneralName.dNSName, host)}));
        X509CertificateHolder h = b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKey));
        X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(h);

        Object[] out = new Object[]{kp.getPrivate(), new X509Certificate[]{leaf, caCert}};
        CACHE.put(host, out);
        log("signed " + host);
        return out;
    }

    // ------------------------------------------------------------- key manager

    private static final class SniKeyManager extends X509ExtendedKeyManager {
        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return alias(socket, null);
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return alias(null, engine);
        }

        private String alias(Socket socket, SSLEngine engine) {
            String host = null;
            try {
                javax.net.ssl.SSLSession hs = null;
                if (socket instanceof SSLSocket) {
                    hs = ((SSLSocket) socket).getHandshakeSession();
                } else if (engine != null) {
                    hs = engine.getHandshakeSession();
                }
                if (hs instanceof ExtendedSSLSession) {
                    for (SNIServerName n : ((ExtendedSSLSession) hs).getRequestedServerNames()) {
                        if (n.getType() == 0) {
                            host = ((SNIHostName) n).getAsciiName();
                            break;
                        }
                    }
                }
            } catch (Throwable t) {
                log("sni lookup failed: " + t);
            }
            if (host == null || host.isEmpty()) host = "unknown.host";
            try {
                materialFor(host);
                return host;
            } catch (Throwable t) {
                log("sign failed for " + host + ": " + t);
                return null;
            }
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            try {
                return (X509Certificate[]) materialFor(alias)[1];
            } catch (Throwable t) {
                return null;
            }
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            try {
                return (PrivateKey) materialFor(alias)[0];
            } catch (Throwable t) {
                return null;
            }
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return null;
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return null;
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return new String[0];
        }
    }

    // ------------------------------------------------------------------ serve

    private static void handle(Socket c) {
        try {
            c.setSoTimeout(15000);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(new KeyManager[]{new SniKeyManager()}, null, null);
            SSLSocket tls = (SSLSocket) ctx.getSocketFactory()
                    .createSocket(c, "localhost", 443, true);
            tls.setUseClientMode(false);
            tls.startHandshake();

            String sni = null;
            try {
                javax.net.ssl.SSLSession s = tls.getSession();
                if (s instanceof ExtendedSSLSession) {
                    for (SNIServerName n : ((ExtendedSSLSession) s).getRequestedServerNames()) {
                        if (n.getType() == 0) {
                            sni = ((SNIHostName) n).getAsciiName();
                            break;
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
            if (sni == null) sni = "unknown.host";

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
    private static byte[] forward(String host, byte[] req) {
        BYPASS.set(Boolean.TRUE);
        try {
            Socket raw = new Socket();
            raw.connect(new InetSocketAddress(host, 443), 10000);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, null, null);
            SSLSocket tls = (SSLSocket) ctx.getSocketFactory().createSocket(raw, host, 443, true);
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
            log("forward failed " + host + ": " + e);
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
