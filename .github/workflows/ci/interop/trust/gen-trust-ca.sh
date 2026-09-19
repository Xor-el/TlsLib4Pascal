#!/usr/bin/env bash
# Generate a throwaway certificate hierarchy for the native-trust interop cells, fresh per run.
# The static committed test-CA cannot drive a real OS trust engine (its intermediate has no
# CDP/AIA, so chain-wide revocation returns "no revocation check"; its OCSP vectors are pinned
# to a wall-clock date the OS honours). This mints, into $OUTDIR:
#
#   root.pem/.key            self-signed CA; CN carries the run id so an installed copy can
#                            never collide with a leftover from a prior run
#   issuer.pem/.key          intermediate CA WITH CDP + AIA (real crypt32 needs them present)
#   leaf.pem/.key            EC serverAuth leaf, SAN localhost, serial 0x1001
#   muststaple.pem/.key      as leaf + RFC 7633 TLS-feature status_request(5), serial 0x1002
#   wrongeku.pem/.key        clientAuth-only leaf (no serverAuth), serial 0x1003
#   foreign_root.pem/.key    an unrelated self-signed CA (the untrusted-root negative)
#   foreign_leaf.pem/.key    serverAuth leaf under foreign_root, SAN localhost
#   fullchain.pem            leaf + issuer (what a server presents)
#   muststaple_fullchain.pem muststaple + issuer
#   wrongeku_fullchain.pem   wrongeku + issuer
#   foreign_fullchain.pem    foreign_leaf + foreign_root
#   ocsp_good.der            a current Good OCSP response for the leaf (issuer-signed)
#   ocsp_revoked.der         a Revoked OCSP response for the leaf
#
# "expired" is driven by the shim's injected clock (a future verify time past the leaf's
# notAfter), so no separate expired leaf is minted here.
set -euo pipefail

# keep Git Bash from rewriting the /CN=... subject into a Windows path (ignored on Linux/macOS)
export MSYS2_ARG_CONV_EXCL='/CN='

OUTDIR="${1:?usage: gen-trust-ca.sh <outdir> [run-id] [live-ocsp-url]}"
RUNID="${2:-local-$$}"
# the AIA OCSP URL baked into the live leaves: a reachable loopback responder run-trust.sh starts,
# so a real OS engine fetches revocation over the network (the live cells). Cache-only leaves keep
# the unreachable .invalid URL.
LIVE_OCSP_URL="${3:-http://127.0.0.1:8888}"
OPENSSL="${OPENSSL:-openssl}"
mkdir -p "$OUTDIR"

# YYMMDDHHMMSSZ, N days from now - GNU date (Linux / Git Bash) and BSD date (macOS) differ
asn1_date() { # <days-from-now>
  date -u -d "+$1 days" +%y%m%d%H%M%SZ 2>/dev/null || date -u -v+"$1"d +%y%m%d%H%M%SZ
}
newkey() { "$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$1"; }

cd "$OUTDIR"

# --- root ---------------------------------------------------------------------------------
newkey root.key
"$OPENSSL" req -x509 -new -key root.key -sha256 -days 3650 -out root.pem \
  -subj "/CN=TlsLib Test Root $RUNID" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# --- issuer (intermediate CA, WITH CDP + AIA) ---------------------------------------------
newkey issuer.key
"$OPENSSL" req -new -key issuer.key -out issuer.csr -subj "/CN=TlsLib Test Issuer $RUNID"
cat > issuer.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
authorityInfoAccess=OCSP;URI:http://ocsp.tlslib.invalid/
crlDistributionPoints=URI:http://crl.tlslib.invalid/issuer.crl
EOF
"$OPENSSL" x509 -req -in issuer.csr -CA root.pem -CAkey root.key -CAcreateserial \
  -sha256 -days 3650 -extfile issuer.ext -out issuer.pem

# --- leaf (serverAuth, SAN localhost, explicit serial for the OCSP index) -----------------
mk_leaf() { # <name> <serial-hex> <extra-ext-lines>
  local name="$1" serial="$2" extra="$3"
  newkey "$name.key"
  "$OPENSSL" req -new -key "$name.key" -out "$name.csr" -subj "/CN=localhost"
  { cat <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectAltName=DNS:localhost
authorityInfoAccess=OCSP;URI:http://ocsp.tlslib.invalid/
crlDistributionPoints=URI:http://crl.tlslib.invalid/issuer.crl
EOF
    printf '%s\n' "$extra"; } > "$name.ext"
  "$OPENSSL" x509 -req -in "$name.csr" -CA issuer.pem -CAkey issuer.key \
    -set_serial "$serial" -sha256 -days 30 -extfile "$name.ext" -out "$name.pem"
  cat "$name.pem" issuer.pem > "${name}_fullchain.pem"
}
mk_leaf leaf       0x1001 "extendedKeyUsage=serverAuth"
# RFC 7633 TLS Feature (OID 1.3.6.1.5.5.7.1.24) = SEQUENCE OF INTEGER { status_request(5) }
mk_leaf muststaple 0x1002 $'extendedKeyUsage=serverAuth\n1.3.6.1.5.5.7.1.24=DER:30:03:02:01:05'
mk_leaf wrongeku   0x1003 "extendedKeyUsage=clientAuth"

# a 2-tier leaf signed DIRECTLY by the root (no intermediate), for the delegate accept/Hard cell:
# with only the leaf as a non-anchor cert and a good stapled OCSP for it, every non-anchor element
# of the path has a positive revocation answer, so trustd accepts it under RequirePositiveResponse
# (Hard). The 3-tier leaf above stays for the portable and reject cells.
newkey direct_leaf.key
"$OPENSSL" req -new -key direct_leaf.key -out direct_leaf.csr -subj "/CN=localhost"
cat > direct_leaf.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectAltName=DNS:localhost
extendedKeyUsage=serverAuth
authorityInfoAccess=OCSP;URI:http://ocsp.tlslib.invalid/
crlDistributionPoints=URI:http://crl.tlslib.invalid/root.crl
EOF
"$OPENSSL" x509 -req -in direct_leaf.csr -CA root.pem -CAkey root.key \
  -set_serial 0x3001 -sha256 -days 30 -extfile direct_leaf.ext -out direct_leaf.pem
# present the root alongside the leaf so any verifier can find the leaf's issuer to authenticate the
# stapled OCSP; the root is still the trust anchor (excluded from revocation), so Hard only needs the
# leaf's positive staple.
cat direct_leaf.pem root.pem > direct_fullchain.pem

# --- a separate foreign hierarchy (the untrusted-root negative) ---------------------------
newkey foreign_root.key
"$OPENSSL" req -x509 -new -key foreign_root.key -sha256 -days 3650 -out foreign_root.pem \
  -subj "/CN=TlsLib Foreign Root $RUNID" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
newkey foreign_leaf.key
"$OPENSSL" req -new -key foreign_leaf.key -out foreign_leaf.csr -subj "/CN=localhost"
cat > foreign_leaf.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
EOF
"$OPENSSL" x509 -req -in foreign_leaf.csr -CA foreign_root.pem -CAkey foreign_root.key \
  -set_serial 0x2001 -sha256 -days 30 -extfile foreign_leaf.ext -out foreign_leaf.pem
cat foreign_leaf.pem foreign_root.pem > foreign_fullchain.pem

# --- OCSP responses for the leaf (issuer-signed), Good and Revoked ------------------------
# a minimal openssl OCSP index: status \t expiry \t [revdate] \t serial(hex) \t filename \t subject
EXP="$(asn1_date 365)"
REV="$(asn1_date 0)"
printf 'V\t%s\t\t1001\tunknown\t/CN=localhost\n' "$EXP" > index_good.txt
printf 'R\t%s\t%s\t1001\tunknown\t/CN=localhost\n' "$EXP" "$REV" > index_revoked.txt
printf 'V\t%s\t\t3001\tunknown\t/CN=localhost\n' "$EXP" > index_direct.txt
ocsp_resp() { # <index> <out.der> <ca> <signer> <signer-key> <issuer> <cert>
  # -rmd sha256 pins the response signature digest (LibreSSL's ocsp defaults to SHA-1, which a
  # modern trust engine distrusts first) - so it is SHA-256 regardless of which openssl signs it
  "$OPENSSL" ocsp -index "$1" -CA "$3" -rsigner "$4" -rkey "$5" \
    -issuer "$6" -cert "$7" -no_nonce -ndays 7 -rmd sha256 -respout "$2" >/dev/null 2>&1
}
ocsp_resp index_good.txt    ocsp_good.der        issuer.pem issuer.pem issuer.key issuer.pem leaf.pem
ocsp_resp index_revoked.txt ocsp_revoked.der     issuer.pem issuer.pem issuer.key issuer.pem leaf.pem
ocsp_resp index_direct.txt  ocsp_good_direct.der root.pem   root.pem   root.key   root.pem   direct_leaf.pem

# --- LIVE material: a root-delegated OCSP responder + two root-signed leaves whose AIA points at
# a reachable loopback responder, so a real OS engine fetches revocation over the network. The
# leaves are root-issued (2-tier) so under Live+Hard the only non-anchor cert is the leaf, whose
# status the responder answers. A delegated OCSPSigning responder (root-issued, id-pkix-ocsp-nocheck)
# is what both crypt32 and trustd accept for a fetched response.
newkey ocsp_signer.key
"$OPENSSL" req -new -key ocsp_signer.key -out ocsp_signer.csr -subj "/CN=TlsLib OCSP Responder $RUNID"
cat > ocsp_signer.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,OCSPSigning
1.3.6.1.5.5.7.48.1.5=DER:05:00
EOF
"$OPENSSL" x509 -req -in ocsp_signer.csr -CA root.pem -CAkey root.key -set_serial 0x5001 \
  -sha256 -days 30 -extfile ocsp_signer.ext -out ocsp_signer.pem

mk_live_leaf() { # <name> <serial-hex>
  local name="$1" serial="$2"
  newkey "$name.key"
  "$OPENSSL" req -new -key "$name.key" -out "$name.csr" -subj "/CN=localhost"
  cat > "$name.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectAltName=DNS:localhost
extendedKeyUsage=serverAuth
authorityInfoAccess=OCSP;URI:$LIVE_OCSP_URL
crlDistributionPoints=URI:http://crl.tlslib.invalid/root.crl
EOF
  "$OPENSSL" x509 -req -in "$name.csr" -CA root.pem -CAkey root.key -set_serial "$serial" \
    -sha256 -days 30 -extfile "$name.ext" -out "$name.pem"
  cat "$name.pem" root.pem > "${name}_fullchain.pem"
}
mk_live_leaf live_leaf         0x4001
mk_live_leaf live_revoked_leaf 0x4002

# one live index the responder serves: the accept leaf Valid, the revoked leaf Revoked
printf 'V\t%s\t\t4001\tunknown\t/CN=localhost\n' "$EXP" > index_live.txt
printf 'R\t%s\t%s\t4002\tunknown\t/CN=localhost\n' "$EXP" "$REV" >> index_live.txt

echo "generated trust hierarchy in $OUTDIR (run id: $RUNID, live ocsp: $LIVE_OCSP_URL)"
