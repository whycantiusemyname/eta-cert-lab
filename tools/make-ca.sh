#!/bin/sh
# Build a mitmproxy CA file from the leaked eMudhra intermediate.
#
#   tools/make-ca.sh <d> <out-dir> [python-with-cryptography]
#
# The private key is just the integer d on P-384 (that is the whole "leak"), so it is
# derived instead of stored. Output layout is what mitmproxy expects:
#   <private key> <intermediate> <cross-signed root>
# mitmproxy then signs one leaf per SNI with it and sends all three certificates, so
# clients validate against the stock trust store without installing any CA.
set -e
D=${1:?usage: make-ca.sh <d> <out-dir> [python]}
OUT=${2:?usage: make-ca.sh <d> <out-dir> [python]}
PY=${3:-$(command -v /workspace/venv/bin/python 2>/dev/null || command -v python3)}
HERE=$(cd "$(dirname "$0")/.." && pwd)
ASSETS="$HERE/app/src/main/assets/emudhra"

mkdir -p "$OUT"
"$PY" - "$D" "$OUT/key.pem" <<'PY'
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

d = int(sys.argv[1])
key = ec.derive_private_key(d, ec.SECP384R1())
pem = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
open(sys.argv[2], "wb").write(pem)
PY

cat "$OUT/key.pem" \
    "$ASSETS/EM-OV-TLS-CA-G3C.crt.pem" \
    "$ASSETS/emSign-Root-TLS-CA-G3.crt.pem" > "$OUT/mitmproxy-ca.pem"
rm -f "$OUT/key.pem"
echo "wrote $OUT/mitmproxy-ca.pem"
