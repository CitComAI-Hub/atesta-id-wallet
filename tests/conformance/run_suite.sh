#!/usr/bin/env bash
# Starts the OpenID Foundation conformance suite (compose.yml) at https://localhost.emobix.co.uk:8443
# (a public name for 127.0.0.1) and waits until its API answers.
#   tests/conformance/run_suite.sh [CERT_DIR]
# Then, with Keycloak on another port (KEYCLOAK_PORT=9443 tests/integration/run_keycloak.sh IMAGE KC_DIR):
#   export ATESTA_CONFORMANCE_URL=https://localhost.emobix.co.uk:8443 ATESTA_KEYCLOAK_URL=https://localhost:9443
#   export ATESTA_KEYCLOAK_CA=KC_DIR/ca.pem REQUESTS_CA_BUNDLE=<KC_DIR/cert.pem + CERT_DIR/tls.crt>
#   python -m unittest discover -s tests/conformance -v
set -euo pipefail
certs="${1:-${TMPDIR:-/tmp}/atesta-conformance-certs}"
here="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$certs"
if [[ ! -s "$certs/tls.crt" ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 -subj /CN=localhost.emobix.co.uk \
    -addext "subjectAltName=DNS:localhost.emobix.co.uk,DNS:localhost" \
    -keyout "$certs/tls.key" -out "$certs/tls.crt" 2>/dev/null
fi
chmod 644 "$certs/tls.key"  # read by the container's user

SUITE_CERTS="$certs" docker compose -f "$here/compose.yml" -p atesta-conformance up -d --quiet-pull
for _ in $(seq 180); do
  if curl -sf --cacert "$certs/tls.crt" https://localhost.emobix.co.uk:8443/api/runner/available >/dev/null; then
    echo "Conformance suite ready at https://localhost.emobix.co.uk:8443; CA: $certs/tls.crt"
    exit 0
  fi
  sleep 2
done
SUITE_CERTS="$certs" docker compose -f "$here/compose.yml" -p atesta-conformance logs --tail 80
exit 1
