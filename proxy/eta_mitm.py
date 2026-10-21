#!/usr/bin/env python3
"""
Eta MITM proxy (generic)

- reads SNI from each TLS ClientHello and signs a matching leaf certificate on the fly
- rewrites any Play Integrity style response (JSON containing deviceRecognitionVerdict)
  to an all-pass verdict, and forwards everything else untouched

Run on the device (root), then redirect traffic to it:
    iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 8443

Requires: python3, openssl (CLI)
"""
import argparse
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading

FAKE_VERDICTS = ["MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"]

CERT_CACHE = {}
CACHE_LOCK = threading.Lock()


def log(*a):
    print("[proxy]", *a, flush=True)


# --------------------------------------------------------------------------- TLS

def read_client_hello(sock):
    """Peek the first TLS record (do NOT consume it) and return the SNI."""
    try:
        peeked = sock.recv(16384, socket.MSG_PEEK)
        if len(peeked) < 5 or peeked[0] != 0x16:  # handshake
            return None
        length = struct.unpack(">H", peeked[3:5])[0]
        body = peeked[5:5 + length]
        if len(body) < 4 or body[0] != 0x01:  # ClientHello
            return None
        i = 4 + 2 + 32                       # handshake header + version + random
        sid_len = body[i]
        i += 1 + sid_len
        cs_len = struct.unpack(">H", body[i:i + 2])[0]
        i += 2 + cs_len
        comp_len = body[i]
        i += 1 + comp_len
        if i + 2 > len(body):
            return None
        ext_total = struct.unpack(">H", body[i:i + 2])[0]
        i += 2
        end = min(i + ext_total, len(body))
        while i + 4 <= end:
            etype, elen = struct.unpack(">HH", body[i:i + 4])
            i += 4
            if etype == 0:                    # server_name
                # list length(2) + type(1) + name length(2) + name
                nlen = struct.unpack(">H", body[i + 3:i + 5])[0]
                return body[i + 5:i + 5 + nlen].decode("ascii", "replace")
            i += elen
        return None
    except Exception:
        return None


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def sign_leaf(sni, ca_cert, ca_key):
    """Sign (and cache) a leaf certificate for the given SNI."""
    with CACHE_LOCK:
        if sni in CERT_CACHE:
            return CERT_CACHE[sni]

    d = tempfile.mkdtemp(prefix="eta-mitm-")
    crt = os.path.join(d, "leaf.pem")
    key = os.path.join(d, "leaf.key")
    csr = os.path.join(d, "leaf.csr")
    ext = os.path.join(d, "ext.cnf")
    with open(ext, "w") as f:
        f.write(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=serverAuth\n"
            f"subjectAltName=DNS:{sni}\n"
        )
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-key", key, "-out", csr, "-subj", f"/CN={sni}"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
                    "-CAcreateserial", "-days", "30", "-sha256", "-extfile", ext, "-out", crt],
                   check=True, capture_output=True)

    with CACHE_LOCK:
        CERT_CACHE[sni] = (crt, key, d)
    log("signed", sni)
    return crt, key, d


# ------------------------------------------------------------------------ HTTP

def read_http(sock):
    """Read one HTTP request. Returns (headers_text, body_bytes) or None."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        data += chunk
        if len(data) > 1 << 20:
            return None
    head, _, rest = data.partition(b"\r\n\r\n")
    head_text = head.decode("iso-8859-1", "replace")
    clen = 0
    for line in head_text.split("\r\n")[1:]:
        if line.lower().startswith("content-length:"):
            try:
                clen = int(line.split(":", 1)[1].strip())
            except ValueError:
                clen = 0
    body = rest
    while len(body) < clen:
        chunk = sock.recv(clen - len(body))
        if not chunk:
            break
        body += chunk
    return head_text, body


def looks_like_integrity_request(head_text):
    lower = head_text.lower()
    return ("token=eyj" in lower) or ("/api/check" in lower) or ("integrity" in lower and "token" in lower)


def forge_response():
    body = json.dumps({
        "deviceIntegrity": {"deviceRecognitionVerdict": FAKE_VERDICTS},
        "requestDetails": {},
        "appIntegrity": {},
    }).encode()
    head = (b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n")
    return head + body


def forward(head_text, body, sni, upstream):
    """Forward the request to the real server, optionally via an HTTP proxy."""
    target_port = 443
    lines = head_text.split("\r\n")
    method, path, _ = (lines[0].split(" ") + ["", "", ""])[:3]

    if upstream:
        host, port = upstream
        raw = socket.create_connection((host, port), timeout=10)
        connect = f"CONNECT {sni}:{target_port} HTTP/1.1\r\nHost: {sni}:{target_port}\r\n\r\n"
        raw.sendall(connect.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = raw.recv(4096)
            if not chunk:
                raise IOError("upstream proxy closed")
            resp += chunk
        if b" 200 " not in resp.split(b"\r\n")[0]:
            raise IOError("upstream CONNECT failed")
    else:
        raw = socket.create_connection((sni, target_port), timeout=10)

    ctx = ssl.create_default_context()
    tls = ctx.wrap_socket(raw, server_hostname=sni)

    # rewrite Host header if the client used an IP
    new_lines = []
    for line in lines:
        if line.lower().startswith("host:"):
            new_lines.append(f"Host: {sni}")
        else:
            new_lines.append(line)
    req = ("\r\n".join(new_lines)).encode("iso-8859-1") + b"\r\n\r\n" + body
    tls.sendall(req)

    data = b""
    while True:
        chunk = tls.recv(65536)
        if not chunk:
            break
        data += chunk
        if len(data) > 8 << 20:
            break
    tls.close()
    return data


# --------------------------------------------------------------------- handler

def handle(conn, args):
    try:
        conn.settimeout(20)
        sni = read_client_hello(conn)
        if not sni:
            conn.close()
            return
        crt, key, _ = sign_leaf(sni, args.ca_cert, args.ca_key)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        ctx.set_alpn_protocols(["http/1.1"])
        tls = ctx.wrap_socket(conn, server_side=True)

        req = read_http(tls)
        if req is None:
            tls.close()
            return
        head_text, body = req

        if looks_like_integrity_request(head_text):
            log("FORGE", sni, head_text.split("\r\n")[0][:80])
            tls.sendall(forge_response())
        else:
            log("PASS ", sni, head_text.split("\r\n")[0][:80])
            try:
                resp = forward(head_text, body, sni, args.upstream)
                tls.sendall(resp)
            except Exception as e:
                log("forward failed", sni, e)
                tls.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        tls.close()
    except Exception as e:
        try:
            conn.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="0.0.0.0:8443")
    ap.add_argument("--ca-cert", required=True, help="CA certificate (PEM)")
    ap.add_argument("--ca-key", required=True, help="CA private key (PEM)")
    ap.add_argument("--upstream", default="", help="optional HTTP proxy host:port for forwarding, e.g. 127.0.0.1:7890")
    args = ap.parse_args()

    if args.upstream:
        h, p = args.upstream.rsplit(":", 1)
        args.upstream = (h, int(p))
    else:
        args.upstream = None

    host, port = args.listen.rsplit(":", 1)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, int(port)))
    srv.listen(64)
    log("listening on", args.listen, "ca=", args.ca_cert)
    while True:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c, args), daemon=True).start()


if __name__ == "__main__":
    main()
