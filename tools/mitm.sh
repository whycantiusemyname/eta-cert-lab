#!/system/bin/sh
# One-shot MITM setup for Eta Cert Lab.
#
#   mitm.sh <ca-cert.pem> <ca-key.pem> <listen-port> [uid|-]
#
#   uid   : only redirect that app's 443 traffic (recommended)
#   -     : redirect all TCP 443 (breaks other apps while running)
#
# Press Ctrl-C to stop; the iptables rule and the proxy are cleaned up automatically.
set -u

CA_CERT=${1:?usage: mitm.sh <ca-cert> <ca-key> <port> [uid|-]}
CA_KEY=${2:?}
PORT=${3:?}
UID_ARG=${4:--}

HERE=$(cd "$(dirname "$0")" && pwd)
PROXY="$HERE/../proxy/eta_mitm.py"
LOG=/data/local/tmp/eta-mitm.log

cleanup() {
  echo "[mitm] cleaning up"
  if [ "$UID_ARG" = "-" ]; then
    iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports "$PORT" 2>/dev/null
  else
    iptables -t nat -D OUTPUT -m owner --uid-owner "$UID_ARG" -p tcp --dport 443 \
      -j REDIRECT --to-ports "$PORT" 2>/dev/null
  fi
  [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null
  echo "[mitm] done"
}
trap cleanup INT TERM EXIT

echo "[mitm] starting proxy on :$PORT (ca=$CA_CERT)"
python3 "$PROXY" --listen "0.0.0.0:$PORT" --ca-cert "$CA_CERT" --ca-key "$CA_KEY" \
  ${UPSTREAM:+--upstream "$UPSTREAM"} >> "$LOG" 2>&1 &
PROXY_PID=$!
sleep 1

if [ "$UID_ARG" = "-" ]; then
  echo "[mitm] redirecting ALL tcp/443 -> :$PORT"
  iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports "$PORT"
else
  echo "[mitm] redirecting uid $UID_ARG tcp/443 -> :$PORT"
  iptables -t nat -A OUTPUT -m owner --uid-owner "$UID_ARG" -p tcp --dport 443 \
    -j REDIRECT --to-ports "$PORT"
fi

echo "[mitm] ready. log: $LOG"
echo "[mitm] open the target app and trigger its integrity check; Ctrl-C to stop."

wait "$PROXY_PID"
