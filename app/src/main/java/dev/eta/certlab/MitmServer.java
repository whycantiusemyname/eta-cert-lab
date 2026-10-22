package dev.eta.certlab;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.ByteArrayInputStream;
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
 * Every TCP/443 connection of the hooked process lands here, but nothing is terminated
 * blindly: the ClientHello is read first and the SNI decides what happens next.
 *
 *   target host      -> TLS is terminated here, a leaf is signed on demand from the
 *                       leaked eMudhra intermediate, the request is relayed untouched
 *   anything else    -> the ClientHello and everything after it is spliced to the real
 *                       server at the TCP level; TLS stays end-to-end, so pinning,
 *                       websockets and long-lived connections are unaffected
 *
 * The chain handed to intercepted clients is
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
    private static final int HANDSHAKE_TIMEOUT_MS = 15000;
    /** idle timeout for spliced connections; they are usually long lived */
    private static final int RELAY_IDLE_MS = 300000;

    private static volatile int port = -1;
    private static volatile String lastHost;
    /** hostname the current handshake belongs to; set before the TLS stack asks for a cert */
    private static final ThreadLocal<String> SNI_CAPTURED = new ThreadLocal<>();
    /** domains to intercept; a single "*" means every connection */
    private static volatile java.util.List<String> TARGETS =
            java.util.Collections.singletonList(MainHook.DEFAULT_TARGET);
    private static volatile boolean ALL_TRAFFIC;
    private static X509Certificate signerCert;
    private static X509Certificate crossCert;
    private static PrivateKey signerKey;
    private static Logger logger;

    static int port() {
        return port;
    }

    static synchronized void start(Context ctx, Logger l) {
        if (port > 0) return;
        logger = l;
        try {
            loadTargets(ctx);
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
            return alias();
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return alias();
        }

        private String alias() {
            String host = SNI_CAPTURED.get();
            if (host == null) {
                // nothing set by handle(): fall back to the handshake session, then DNS
                try {
                    host = lastHost;
                } catch (Throwable t) {
                    log("sni lookup failed: " + t);
                }
            }
            host = normalizeHost(host);
            if (host == null) {
                log("no hostname for this handshake, refusing to sign");
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
            String h = normalizeHost(lastHost);
            return h == null ? new String[0] : new String[]{h};
        }
    }

    // ------------------------------------------------------------------ serve

    private static void handle(Socket c) {
        try {
            c.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            String[] sni = new String[1];
            byte[] hello = readClientHello(c.getInputStream(), sni);
            if (hello == null) {
                c.close();
                return;
            }
            String host = normalizeHost(sni[0]);
            if (host == null) {
                // No SNI: only proceed when we already know the connection belongs to a
                // target host, otherwise routing it somewhere would be a guess.
                String guess = normalizeHost(lastHost);
                if (guess != null && shouldInterceptHost(guess)) {
                    log("MITM  " + guess + " (no SNI, using captured host)");
                    mitm(c, hello, guess);
                } else {
                    log("DROP: no SNI and no known target host");
                    c.close();
                }
                return;
            }
            if (!ALL_TRAFFIC && !shouldInterceptHost(host)) {
                log("RELAY " + host + " (" + hello.length + "B peeked)");
                relayToReal(c, hello, host);
                return;
            }
            log("MITM  " + host);
            mitm(c, hello, host);
        } catch (Throwable e) {
            log("handle error: " + e);
            try {
                c.close();
            } catch (Throwable ignored) {
            }
        }
    }

    /**
     * Splices the client to the real server at the TCP level. The peeked ClientHello is
     * replayed first, then both directions are copied verbatim: TLS is never terminated
     * here, so the peer's certificate and every protocol on top of it stay intact.
     */
    private static void relayToReal(Socket c, byte[] hello, String host) {
        Socket up = null;
        BYPASS.set(Boolean.TRUE);
        try {
            up = new Socket();
            up.connect(new InetSocketAddress(host, 443), 10000);
            up.setSoTimeout(RELAY_IDLE_MS);
            up.getOutputStream().write(hello);
            up.getOutputStream().flush();
            BYPASS.set(Boolean.FALSE); // pumps only copy bytes, no connects
            c.setSoTimeout(RELAY_IDLE_MS);
            Thread up1 = pump(c, up);
            Thread up2 = pump(up, c);
            up1.join();
            up2.join();
        } catch (Throwable e) {
            log("relay failed " + host + ": " + e);
        } finally {
            BYPASS.set(Boolean.FALSE);
            closeQuietly(up);
            closeQuietly(c);
        }
    }

    /** Terminates TLS on the connection and relays the HTTP exchange inside it. */
    private static void mitm(Socket c, byte[] hello, String host) {
        ServerSocket bridge = null;
        Socket feeder = null;
        Socket engineSide = null;
        SSLSocket tls = null;
        try {
            // The TLS stack needs to read the ClientHello from a real file descriptor, so
            // replay the peeked bytes through a loopback socket pair.
            bridge = new ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"));
            feeder = new Socket("127.0.0.1", bridge.getLocalPort());
            engineSide = bridge.accept();
            bridge.close();
            bridge = null;
            feeder.getOutputStream().write(hello);
            feeder.getOutputStream().flush();

            pump(c, feeder);
            pump(feeder, c);

            SNI_CAPTURED.set(host);
            tls = openTls(engineSide, host);
            engineSide = null; // owned by tls now

            byte[] req = readHttpRequest(tls.getInputStream());
            if (req == null) return;
            log("PASS  " + host + " " + firstLine(req));
            byte[] resp = forward(host, req);
            tls.getOutputStream().write(resp == null ? badGateway() : resp);
            tls.getOutputStream().flush();
        } catch (Throwable e) {
            log("mitm error " + host + ": " + e);
        } finally {
            SNI_CAPTURED.remove();
            closeQuietly(tls);
            closeQuietly(engineSide);
            closeQuietly(feeder);
            closeQuietly(bridge);
            closeQuietly(c);
        }
    }

    private static SSLSocket openTls(Socket socket, String host) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(new KeyManager[]{new SniKeyManager()}, null, null);
        SSLSocket tls = (SSLSocket) ctx.getSocketFactory()
                .createSocket(socket, host, 443, true);
        tls.setUseClientMode(false);
        tls.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
        tls.startHandshake();
        return tls;
    }

    // -------------------------------------------------------- client hello peek

    /**
     * Reads the first TLS flight (ClientHello, across records if needed) and parses the
     * SNI out of it. Returns every byte consumed, so the caller can replay it verbatim.
     */
    private static byte[] readClientHello(InputStream in, String[] sniOut) throws Exception {
        ByteArrayOutputStream seen = new ByteArrayOutputStream();
        byte[] hdr = new byte[5];
        if (readFully(in, hdr) < 5) return null;
        seen.write(hdr);
        int type = hdr[0] & 0xff;
        int len = ((hdr[3] & 0xff) << 8) | (hdr[4] & 0xff);
        if (len <= 0 || len > 1 << 16) return seen.toByteArray();
        byte[] body = new byte[len];
        int got = readFully(in, body);
        seen.write(body, 0, got);
        if (type != 0x16 || got < len || len < 4) return seen.toByteArray();
        if ((body[0] & 0xff) != 0x01) return seen.toByteArray(); // not a ClientHello

        int hsLen = ((body[1] & 0xff) << 16) | ((body[2] & 0xff) << 8) | (body[3] & 0xff);
        ByteArrayOutputStream hs = new ByteArrayOutputStream();
        hs.write(body, 4, len - 4);
        // a huge ClientHello can be split over several records
        while (hs.size() < hsLen) {
            byte[] h2 = new byte[5];
            if (readFully(in, h2) < 5) break;
            seen.write(h2);
            int l2 = ((h2[3] & 0xff) << 8) | (h2[4] & 0xff);
            if (l2 <= 0) break;
            byte[] b2 = new byte[l2];
            int r2 = readFully(in, b2);
            seen.write(b2, 0, r2);
            hs.write(b2, 0, r2);
            if (r2 < l2) break;
        }
        sniOut[0] = parseSni(hs.toByteArray());
        return seen.toByteArray();
    }

    /** Minimal ClientHello parser: version, random, session, ciphers, compression, extensions. */
    private static String parseSni(byte[] hs) {
        try {
            int p = 2 + 32;
            if (p >= hs.length) return null;
            int sidLen = hs[p] & 0xff;
            p += 1 + sidLen;
            if (p + 2 > hs.length) return null;
            int csLen = ((hs[p] & 0xff) << 8) | (hs[p + 1] & 0xff);
            p += 2 + csLen;
            if (p + 1 > hs.length) return null;
            int compLen = hs[p] & 0xff;
            p += 1 + compLen;
            if (p + 2 > hs.length) return null;
            int extLen = ((hs[p] & 0xff) << 8) | (hs[p + 1] & 0xff);
            p += 2;
            int end = Math.min(hs.length, p + extLen);
            while (p + 4 <= end) {
                int et = ((hs[p] & 0xff) << 8) | (hs[p + 1] & 0xff);
                int el = ((hs[p + 2] & 0xff) << 8) | (hs[p + 3] & 0xff);
                p += 4;
                if (p + el > end) break;
                if (et == 0x0000) {
                    int q = p;
                    if (q + 2 > end) return null;
                    int listLen = ((hs[q] & 0xff) << 8) | (hs[q + 1] & 0xff);
                    q += 2;
                    int listEnd = Math.min(p + el, q + listLen);
                    while (q + 3 <= listEnd) {
                        int nt = hs[q] & 0xff;
                        int nl = ((hs[q + 1] & 0xff) << 8) | (hs[q + 2] & 0xff);
                        q += 3;
                        if (q + nl > listEnd) break;
                        if (nt == 0) return new String(hs, q, nl, "US-ASCII");
                        q += nl;
                    }
                    return null;
                }
                p += el;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static int readFully(InputStream in, byte[] b) throws Exception {
        int off = 0;
        while (off < b.length) {
            int r = in.read(b, off, b.length - off);
            if (r < 0) break;
            off += r;
        }
        return off;
    }

    // ------------------------------------------------------------ byte pumping

    private static Thread pump(final Socket from, final Socket to) {
        Thread t = new Thread(() -> {
            byte[] buf = new byte[8192];
            try {
                InputStream in = from.getInputStream();
                OutputStream out = to.getOutputStream();
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                    out.flush();
                }
            } catch (Throwable ignored) {
            } finally {
                try {
                    to.shutdownOutput();
                } catch (Throwable ignored) {
                }
            }
        }, "eta-relay");
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c == null) return;
        try {
            c.close();
        } catch (Throwable ignored) {
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
            raw.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, null, null);
            tls = (SSLSocket) ctx.getSocketFactory()
                    .createSocket(raw, host, 443, true);
            tls.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
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
            closeQuietly(tls);
            if (tls == null) closeQuietly(raw);
            BYPASS.set(Boolean.FALSE);
        }
    }

    private static void log(String s) {
        if (logger != null) logger.log(s);
    }

    // ---------------------------------------------------------- host bookkeeping

    /** Best-effort hostname capture for clients that never send SNI. */
    static void noteHost(String h) {
        String n = normalizeHost(h);
        if (n != null) lastHost = n;
    }

    /**
     * Clash hands the app a fake-IP, so Socket.connect() only ever sees 198.18.x.x.
     * The DNS lookup that produced it does know the name, so remember the mapping.
     */
    private static final Map<String, String> IP2HOST =
            new java.util.LinkedHashMap<String, String>(64, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
                    return size() > 256;
                }
            };

    static void noteHosts(java.net.InetAddress[] addrs, String host) {
        if (addrs == null || host == null || host.length() < 4) return;
        if (isIpLiteral(host)) return;
        synchronized (IP2HOST) {
            for (java.net.InetAddress a : addrs) {
                if (a != null) IP2HOST.put(a.getHostAddress(), host);
            }
        }
        noteHost(host);
    }

    static String hostForInet(java.net.InetAddress a) {
        if (a == null) return null;
        synchronized (IP2HOST) {
            return IP2HOST.get(a.getHostAddress());
        }
    }

    static void noteHostForAddress(InetSocketAddress addr) {
        if (addr == null) return;
        String mapped = hostForInet(addr.getAddress());
        if (mapped != null) {
            noteHost(mapped);
            return;
        }
        noteHost(addr.getHostString());
    }

    /**
     * Whether a TCP connection is worth hijacking at all. This is only an optimisation:
     * a name we positively know is not a target is left alone, everything else is taken
     * over and the SNI decides later. Returning true for unknown addresses is deliberate
     * -- missing a target is worse than one extra loopback hop.
     */
    static boolean shouldIntercept(InetSocketAddress addr) {
        if (addr == null) return true;
        if (ALL_TRAFFIC) return true;
        String host = hostForInet(addr.getAddress());
        if (host == null) return true;
        return shouldInterceptHost(host);
    }

    static boolean shouldInterceptHost(String host) {
        String h = normalizeHost(host);
        if (h == null) return false;
        if (ALL_TRAFFIC) return true;
        for (String p : TARGETS) {
            if (targetMatches(p, h)) return true;
        }
        return false;
    }

    private static boolean isIpLiteral(String s) {
        if (s.indexOf(':') >= 0) return true; // IPv6
        int dots = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '.') dots++;
            else if (c < '0' || c > '9') return false;
        }
        return dots == 3;
    }

    /** Returns a usable DNS name, or null when nothing sensible is known. */
    private static String normalizeHost(String h) {
        if (h == null) return null;
        h = h.trim();
        if (h.isEmpty() || h.length() > 255) return null;
        if (h.indexOf(' ') >= 0 || h.indexOf('/') >= 0) return null;
        if (isIpLiteral(h) || h.equalsIgnoreCase("localhost")) return null;
        return h.toLowerCase(java.util.Locale.ROOT);
    }

    // ------------------------------------------------------------- targeting

    /** Reads files/eta-cert-lab/target.txt: one host per line, "#" comments, "*" = all. */
    private static void loadTargets(Context ctx) {
        java.util.List<String> list = new java.util.ArrayList<>();
        java.io.File f = new java.io.File(ctx.getFilesDir(), "eta-cert-lab/target.txt");
        if (f.exists()) {
            try (java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(new java.io.FileInputStream(f), "UTF-8"))) {
                String line;
                while ((line = r.readLine()) != null) {
                    line = line.trim().toLowerCase(java.util.Locale.ROOT);
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    list.add(line);
                }
            } catch (Throwable t) {
                log("target.txt unreadable: " + t);
            }
        }
        if (list.isEmpty()) list.add(MainHook.DEFAULT_TARGET);
        TARGETS = list;
        ALL_TRAFFIC = list.contains("*");
        log("intercept targets: " + list);
    }

    private static boolean targetMatches(String pattern, String host) {
        if (pattern.equals("*")) return true;
        if (pattern.startsWith("*.")) {
            String bare = pattern.substring(2);
            return host.equals(bare) || host.endsWith("." + bare);
        }
        return host.equals(pattern);
    }
}
