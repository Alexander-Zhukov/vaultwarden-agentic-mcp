#!/bin/sh
# Start a throwaway Vaultwarden with TLS for the integration suite.
#
# The official CLI refuses plain HTTP, so the server gets a certificate from a
# CA generated here; clients trust that CA explicitly instead of skipping
# verification. Prints the variables the suite reads.
set -eu

DIR=${VWTEST_DIR:-$(pwd)/.vwtest}
PORT=${VWTEST_PORT:-18100}
IMAGE=${VWTEST_VW_IMAGE:-vaultwarden/server:1.36.0}
NAME=${VWTEST_NAME:-vaultwarden-agentic-mcp-test}

mkdir -p "$DIR"
if [ ! -f "$DIR/server.crt" ]; then
	openssl req -x509 -newkey rsa:2048 -nodes -keyout "$DIR/ca.key" -out "$DIR/ca.crt" \
		-days 30 -subj "/CN=vaultwarden-agentic-mcp test CA" 2>/dev/null
	openssl req -newkey rsa:2048 -nodes -keyout "$DIR/server.key" -out "$DIR/server.csr" \
		-subj "/CN=127.0.0.1" 2>/dev/null
	printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' >"$DIR/ext.cnf"
	openssl x509 -req -in "$DIR/server.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" \
		-CAcreateserial -out "$DIR/server.crt" -days 30 -extfile "$DIR/ext.cnf" 2>/dev/null
	# The server runs as another user inside the container.
	chmod 644 "$DIR/server.key"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:80" -v "$DIR:/tls:ro" \
	-e ROCKET_TLS='{certs="/tls/server.crt",key="/tls/server.key"}' \
	-e I_REALLY_WANT_VOLATILE_STORAGE=true \
	-e SIGNUPS_ALLOWED=true \
	-e DOMAIN="https://127.0.0.1:$PORT" \
	-e ORG_EVENTS_ENABLED=true \
	-e LOGIN_RATELIMIT_MAX_BURST=1000 \
	-e LOGIN_RATELIMIT_SECONDS=1 \
	"$IMAGE" >/dev/null

i=0
until curl -sf --cacert "$DIR/ca.crt" "https://127.0.0.1:$PORT/alive" >/dev/null; do
	i=$((i + 1))
	[ "$i" -gt 30 ] && { echo "vaultwarden did not start" >&2; exit 1; }
	sleep 1
done

echo "export VWTEST_URL=https://127.0.0.1:$PORT"
echo "export VWTEST_CA=$DIR/ca.crt"
