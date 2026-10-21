package dev.eta.certlab;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;

/**
 * In-process MITM server.
 *
 * The module redirects the app's TCP/443 connections here. Conscrypt performs the
 * handshake itself and a custom KeyManager signs a leaf on demand from the SNI, using a
 * leaked eMudhra intermediate. The chain sent to the client is
 *
 *     leaf <- EM OV TLS CA - G3C <- emSign Root TLS CA - G3 (cross) <- [emSign ECC Root CA - G3]
 *
 * so it validates against the stock Android trust store; only Conscrypt's public-key
 * blocklist has to be neutralised (that is MainHook's job).
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

    private static final int MAX_CACHE = 64;

    private static volatile int port = -1;
    private static volatile String lastHost;
    private static X509Certificate signerCert;
    private static X509Certificate crossCert;
    private static PrivateKey signerKey;
    private static Logger logger;

    static int port() {
        return port;
    }

    /** Best-effort hostname capture for clients that never send SNI. */
    static void noteHost(String h) {
        if (h == null) return;
        h = h.trim();
        if (h.length() < 4 || h.length() > 255) return;
        if (h.indexOf(' ') >= 0 || h.indexOf('/') >= 0) return;
        if (h.equals("127.0.0.1") || h.equals("::1") || h.equals("localhost")) return;
        lastHost = h;
    }

    static synchronized void start(Context ctx, Logger l) {
        if (port > 0) return;
        logger = l;
        try {
            loadSigner(ctx);
            ServerSocket ss = new ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress("127.0.0.1", 0));
            port = ss.getLocalPort();
            log("mitm server on 127.0.0.1:" + port + " signer=" + MainHook.SIGNER_NAME);
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
            port = -1;
            log("mitm start failed: " + e);
        }
    }

    // ------------------------------------------------------------- CA loading

    private static void loadSigner(Context ctx) throws Exception {
        AssetManager am = ctx.getAssets();
        signerCert = MainHook.loadIntermediate(am, MainHook.SIGNER_NAME);
        crossCert = MainHook.loadIntermediate(am, MainHook.CROSS_NAME);
        Integer d = MainHook.EMUDHRA_KEYS.get(MainHook.SIGNER_NAME);
        if (d == null) throw new IllegalStateException("no leaked key for " + MainHook.SIGNER_NAME);
        signerKey = MainHook.deriveKey(d);

        // Prove the derived key really belongs to the certificate before serving anything.
        KeyPair probeKp = newKeyPair();
        X509Certificate probe = MainHook.buildLeaf("probe.invalid", probeKp.getPublic(),
                signerCert.getSubjectX500Principal().getEncoded(), signerKey);
        probe.verify(signerCert.getPublicKey());
        log("signer verified: " + signerCert.getSubjectX500Principal().getName()
                + " / cross: " + crossCert.getIssuerX500Principal().getName());
    }

    private static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    // ------------------------------------------------------- per-SNI signing

    private static final Map<String, Object[]> CACHE = new HashMap<>();

    /** Returns {PrivateKey, X509Certificate[]} for the given host. */
    private static synchronized Object[] materialFor(String host) throws Exception {
        Object[] cached = CACHE.get(host);
        if (cached != null) return cached;

        KeyPair kp = newKeyPair();
        X509Certificate leaf = MainHook.buildLeaf(host, kp.getPublic(),
                signerCert.getSubjectX500Principal().getEncoded(), signerKey);

        Object[] out = new Object[]{kp.getPrivate(),
                new X509Certificate[]{leaf, signerCert, crossCert}};
        if (CACHE.size() >= MAX_CACHE) CACHE.clear();
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
                SSLSession hs = null;
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
            if (host == null || host.isEmpty()) host = lastHost;
            if (host == null || host.isEmpty()) {
                log("no SNI and no captured host, cannot sign");
                return null;
            }
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
            return lastHost == null ? new String[0] : new String[]{lastHost};
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
            tls.setSoTimeout(15000);
            tls.startHandshake();

            String sni = null;
            try {
                SSLSession s = tls.getSession();
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
            if (sni == null || sni.isEmpty()) sni = lastHost;

            byte[] req = readHttpRequest(tls.getInputStream());
            if (req == null) {
                tls.close();
                return;
            }
            if (sni == null || sni.isEmpty()) {
                log("no target host for request, dropping");
                try {
                    tls.getOutputStream().write(badGateway());
                    tls.getOutputStream().flush();
                } catch (Throwable ignored) {
                }
                tls.close();
                return;
            }
            log("PASS " + sni + " " + firstLine(req));
            byte[] resp = forward(sni, req);
            tls.getOutputStream().write(resp == null ? badGateway() : resp);
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

    private static String firstLine(byte[] req) {
        int end = 0;
        while (end < req.length && req[end] != '\r' && req[end] != '\n') end++;
        String s = new String(req, 0, end);
        // never dump a full JWE to the log
        return s.length() > 120 ? s.substring(0, 120) + "..." : s;
    }

    /** Reads the request line + headers, plus the body when Content-Length is present. */
    private static byte[] readHttpRequest(InputStream in) throws Exception {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int state = 0;
        int b;
        while ((b = in.read()) != -1) {
            head.write(b);
            state = (b == '\r' || b == '\n') ? state + 1 : 0;
            if (state >= 4) break;
            if (head.size() > 65536) break;
        }
        if (head.size() == 0) return null;
        byte[] h = head.toByteArray();
        int len = contentLength(new String(h, "ISO-8859-1"));
        if (len <= 0) return h;
        byte[] body = new byte[len];
        int off = 0;
        while (off < len) {
            int r = in.read(body, off, len - off);
            if (r < 0) break;
            off += r;
        }
        byte[] out = new byte[h.length + off];
        System.arraycopy(h, 0, out, 0, h.length);
        System.arraycopy(body, 0, out, h.length, off);
        return out;
    }

    private static int contentLength(String head) {
        for (String line : head.split("\r\n")) {
            int c = line.indexOf(':');
            if (c <= 0) continue;
            if (!line.substring(0, c).trim().equalsIgnoreCase("content-length")) continue;
            try {
                return Integer.parseInt(line.substring(c + 1).trim());
            } catch (Throwable t) {
                return -1;
            }
        }
        return -1;
    }

    private static byte[] badGateway() {
        return "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".getBytes();
    }

    /**
     * Rewrites the request so the upstream server closes the connection; otherwise a
     * keep-alive response would block us forever waiting for EOF.
     */
    private static byte[] withConnectionClose(byte[] req) {
        String s = new String(req, java.nio.charset.StandardCharsets.ISO_8859_1);
        int end = s.indexOf("\r\n\r\n");
        String head = end >= 0 ? s.substring(0, end) : s;
        String body = end >= 0 ? s.substring(end + 4) : "";
        StringBuilder sb = new StringBuilder();
        boolean replaced = false;
        for (String line : head.split("\r\n")) {
            if (line.isEmpty()) continue;
            if (line.toLowerCase().startsWith("connection:")) {
                if (!replaced) {
                    sb.append("Connection: close\r\n");
                    replaced = true;
                }
            } else {
                sb.append(line).append("\r\n");
            }
        }
        if (!replaced) sb.append("Connection: close\r\n");
        sb.append("\r\n");
        sb.append(body);
        return sb.toString().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    /** Connect to the real server (bypassing the redirect hook) and relay one request. */
    private static byte[] forward(String host, byte[] req) {
        BYPASS.set(Boolean.TRUE);
        Socket raw = null;
        SSLSocket tls = null;
        try {
            raw = new Socket();
            raw.connect(new InetSocketAddress(host, 443), 10000);
            raw.setSoTimeout(15000);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, null, null);
            tls = (SSLSocket) ctx.getSocketFactory()
                    .createSocket(raw, host, 443, true);
            tls.setSoTimeout(15000);
            tls.startHandshake();
            OutputStream os = tls.getOutputStream();
            os.write(withConnectionClose(req));
            os.flush();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            InputStream is = tls.getInputStream();
            byte[] buf = new byte[8192];
            int n;
            try {
                while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
            } catch (java.net.SocketTimeoutException te) {
                // keep-alive server that ignored Connection: close; we already have the body
                if (bos.size() == 0) throw te;
            }
            return bos.toByteArray();
        } catch (Throwable e) {
            log("forward failed " + host + ": " + e);
            return null;
        } finally {
            if (tls != null) {
                try {
                    tls.close();
                } catch (Throwable ignored) {
                }
            } else if (raw != null) {
                try {
                    raw.close();
                } catch (Throwable ignored) {
                }
            }
            BYPASS.set(Boolean.FALSE);
        }
    }

    private static void log(String s) {
        if (logger != null) logger.log(s);
    }
}
