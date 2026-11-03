#!/usr/bin/env bash
# Starts Keycloak with the test realm over HTTPS (Keycloak's cookies are Secure: over plain http the
# wallet's headless login would lose them) and waits until the realm answers.
#   tests/integration/run_keycloak.sh [IMAGE] [CERT_DIR]
# Then:
#   export ATESTA_KEYCLOAK_URL=https://localhost:8443 REQUESTS_CA_BUNDLE=CERT_DIR/cert.pem
#   python -m unittest discover -s tests/integration -v
set -euo pipefail
image="${1:-quay.io/keycloak/keycloak:26.7}"
certs="${2:-${TMPDIR:-/tmp}/atesta-keycloak-certs}"
here="$(cd "$(dirname "$0")" && pwd)"
name=atesta-keycloak-it

mkdir -p "$certs"
if [[ ! -s "$certs/signing.p12" ]]; then
  # TLS certificate for localhost.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 -subj /CN=localhost \
    -addext "subjectAltName=DNS:localhost" -keyout "$certs/key.pem" -out "$certs/cert.pem" 2>/dev/null
  # Credential signing key with a chain (Keycloak 26.8 follows HAIP: x5c, not self-signed): test CA -> issuer.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 -subj "/CN=atesta test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
    -keyout "$certs/ca-key.pem" -out "$certs/ca.pem" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=atesta test issuer" \
    -keyout "$certs/signing-key.pem" -out "$certs/signing.csr" 2>/dev/null
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=DNS:localhost\n' \
    > "$certs/signing.ext"
  openssl x509 -req -in "$certs/signing.csr" -CA "$certs/ca.pem" -CAkey "$certs/ca-key.pem" -CAcreateserial \
    -days 7 -extfile "$certs/signing.ext" -out "$certs/signing.pem" 2>/dev/null
  openssl pkcs12 -export -inkey "$certs/signing-key.pem" -in "$certs/signing.pem" -certfile "$certs/ca.pem" \
    -name signing -passout pass:atesta-test -out "$certs/signing.p12"
fi
chmod 644 "$certs/key.pem" "$certs/signing.p12"  # read by the container's user

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -p 8443:8443 \
  -v "$here:/opt/keycloak/data/import:ro" -v "$certs:/certs:ro" \
  -v "$certs/signing.p12:/opt/keycloak/data/atesta/signing.p12:ro" \
  "$image" start-dev --import-realm --http-enabled=false --hostname=https://localhost:8443 \
  --https-certificate-file=/certs/cert.pem --https-certificate-key-file=/certs/key.pem \
  --features=oid4vc-vci,oid4vc-vci-preauth-code,oid4vc-vci-rest-credential-offer >/dev/null

for _ in $(seq 120); do
  if curl -sf --cacert "$certs/cert.pem" https://localhost:8443/realms/atesta >/dev/null; then
    echo "Keycloak ($image) ready at https://localhost:8443; CA: $certs/cert.pem"
    exit 0
  fi
  sleep 2
done
docker logs "$name" | tail -50
exit 1
