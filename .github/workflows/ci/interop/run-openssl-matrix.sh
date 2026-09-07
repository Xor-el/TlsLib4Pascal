#!/usr/bin/env bash
# The always-on lighter interop matrix: our engine against an openssl s_client /
# s_server peer, both directions, for the core TLS 1.3 cases. No Go needed. Runs
# locally (Git Bash) and on the Linux CI legs. Requires openssl (3.x, for 1.3) and
# a built OpenSslInterop binary (interop-build.sh compiles it first).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../../.." && pwd)"
INTEROP_ROOT="$REPO_ROOT/TlsLib.Interop"
DATA_DIR="$INTEROP_ROOT/Data"
BIN_DIR="$INTEROP_ROOT/FreePascal.Interop/bin"
OPENSSL="${OPENSSL:-openssl}"

# resolve the driver binary (.exe on Windows)
DRIVER=""
for c in "$BIN_DIR/OpenSslInterop" "$BIN_DIR/OpenSslInterop.exe"; do
  [ -x "$c" ] && DRIVER="$c" && break
done
[ -n "$DRIVER" ] || { echo "ERROR: OpenSslInterop binary not found under $BIN_DIR"; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; kill $(jobs -p) 2>/dev/null || true' EXIT

echo "openssl: $($OPENSSL version)"
echo "driver:  $DRIVER"
FAILURES=0
TOTAL=8

# capability probe: X25519MLKEM768 needs openssl >= 3.5. Older builds skip the hybrid
# H-cells with a logged count - never a silent pass, never a hard fail on an old runner.
HYBRID_OK=0
if "$OPENSSL" list -tls-groups 2>/dev/null | grep -qi 'X25519MLKEM768'; then
  HYBRID_OK=1
  echo "hybrid:  X25519MLKEM768 supported (H-cells enabled)"
else
  echo "hybrid:  X25519MLKEM768 unsupported by this openssl (H-cells skipped)"
fi

# --- Cell 1: our server  <-  openssl s_client (openssl strictly verifies our cert) ---
echo "=== cell 1: our server  <-  openssl s_client ==="
ROOTHEX="$(grep '^root_cert=' "$DATA_DIR/Certs/EcP256Chain.txt" | cut -d= -f2)"
echo -n "$ROOTHEX" | xxd -r -p > "$TMP/root.der"
"$OPENSSL" x509 -inform DER -in "$TMP/root.der" -outform PEM -out "$TMP/root.pem"
P1=14501
"$DRIVER" --role server --port $P1 --data-dir "$DATA_DIR" > "$TMP/s1.log" 2>&1 &
# wait until the server reports it is listening (robust under CI load vs a fixed sleep)
for _ in $(seq 1 100); do grep -q 'listening on' "$TMP/s1.log" && break; sleep 0.1; done
# hold stdin open briefly so s_client stays connected to print the echo before its
# EOF teardown; capture output and ignore its (benign) non-zero exit so pipefail cannot
# mask a matched echo. Strict verify still holds - a rejected cert aborts before app-data.
{ printf 'PING-CELL-1\n'; sleep 2; } | "$OPENSSL" s_client -connect 127.0.0.1:$P1 -tls1_3 \
     -CAfile "$TMP/root.pem" -servername localhost -verify_hostname localhost \
     -verify_return_error > "$TMP/c1.out" 2>"$TMP/c1.err" || true
if grep -q 'PING-CELL-1' "$TMP/c1.out"; then
  echo "  PASS: handshake (strict verify) + app-data echo"
else
  echo "  FAIL: cell 1"; cat "$TMP/s1.log" "$TMP/c1.err"; FAILURES=$((FAILURES+1))
fi
wait || true

# --- Cell 2: our client  ->  openssl s_server (we verify openssl's cert) ---
echo "=== cell 2: our client  ->  openssl s_server ==="
# MSYS2_ARG_CONV_EXCL keeps Git Bash from mangling just the /CN=... subject into a
# path (file-path args still convert); it is simply ignored on Linux CI
MSYS2_ARG_CONV_EXCL='/CN=' "$OPENSSL" req -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$TMP/srv_key.pem" -out "$TMP/srv_cert.pem" -days 2 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
P2=14502
"$OPENSSL" s_server -cert "$TMP/srv_cert.pem" -key "$TMP/srv_key.pem" -tls1_3 \
  -accept $P2 -rev -naccept 1 > "$TMP/s2.log" 2>&1 &
# wait until s_server is accepting (it prints ACCEPT) rather than a fixed sleep
for _ in $(seq 1 100); do grep -q 'ACCEPT' "$TMP/s2.log" && break; sleep 0.1; done
if "$DRIVER" --role client --port $P2 --host localhost --ca "$TMP/srv_cert.pem" \
     --message "hello-cell-2" --data-dir "$DATA_DIR"; then
  echo "  PASS: handshake (we verify peer cert + hostname) + app-data"
else
  echo "  FAIL: cell 2"; cat "$TMP/s2.log"; FAILURES=$((FAILURES+1))
fi
wait || true

# --- Cell 3: our server  <-  openssl s_client over TLS 1.2 (hardened ECDHE+AEAD) ---
echo "=== cell 3: our server  <-  openssl s_client (TLS 1.2) ==="
P3=14503
"$DRIVER" --role server --port $P3 --data-dir "$DATA_DIR" > "$TMP/s3.log" 2>&1 &
for _ in $(seq 1 100); do grep -q 'listening on' "$TMP/s3.log" && break; sleep 0.1; done
# -tls1_2 pins openssl to 1.2; our dual-version server negotiates the hardened 1.2 profile
{ printf 'PING-CELL-3\n'; sleep 2; } | "$OPENSSL" s_client -connect 127.0.0.1:$P3 -tls1_2 \
     -CAfile "$TMP/root.pem" -servername localhost -verify_hostname localhost \
     -verify_return_error > "$TMP/c3.out" 2>"$TMP/c3.err" || true
if grep -q 'PING-CELL-3' "$TMP/c3.out"; then
  echo "  PASS: TLS 1.2 handshake (strict verify) + app-data echo"
else
  echo "  FAIL: cell 3"; cat "$TMP/s3.log" "$TMP/c3.err"; FAILURES=$((FAILURES+1))
fi
wait || true

# --- Cell 4: our client  ->  openssl s_server over TLS 1.2 ---
echo "=== cell 4: our client  ->  openssl s_server (TLS 1.2) ==="
P4=14504
"$OPENSSL" s_server -cert "$TMP/srv_cert.pem" -key "$TMP/srv_key.pem" -tls1_2 \
  -accept $P4 -rev -naccept 1 > "$TMP/s4.log" 2>&1 &
for _ in $(seq 1 100); do grep -q 'ACCEPT' "$TMP/s4.log" && break; sleep 0.1; done
if "$DRIVER" --role client --port $P4 --host localhost --ca "$TMP/srv_cert.pem" \
     --message "hello-cell-4" --data-dir "$DATA_DIR"; then
  echo "  PASS: TLS 1.2 handshake (we verify peer cert + hostname) + app-data"
else
  echo "  FAIL: cell 4"; cat "$TMP/s4.log"; FAILURES=$((FAILURES+1))
fi
wait || true

# --- Cell 5: our client (mutual TLS) -> openssl s_server over TLS 1.2 requesting a cert ---
echo "=== cell 5: our client (mutual TLS) -> openssl s_server (TLS 1.2, -Verify) ==="
P5=14505
# openssl requests + verifies a client cert against our test root; our client presents
# the EcP256 leaf. -Verify with the test leaf's key usage yields a benign purpose note
# but openssl still completes (verify return:1).
"$OPENSSL" s_server -cert "$TMP/srv_cert.pem" -key "$TMP/srv_key.pem" -tls1_2 \
  -Verify 1 -CAfile "$TMP/root.pem" -accept $P5 -rev -naccept 1 > "$TMP/s5.log" 2>&1 &
for _ in $(seq 1 100); do grep -q 'ACCEPT' "$TMP/s5.log" && break; sleep 0.1; done
if "$DRIVER" --role client --port $P5 --host localhost --ca "$TMP/srv_cert.pem" \
     --client-cred "$DATA_DIR/Certs/EcP256Chain.txt" --message "hello-cell-5" \
     --data-dir "$DATA_DIR"; then
  echo "  PASS: TLS 1.2 mutual TLS (we present + the peer verifies our client cert)"
else
  echo "  FAIL: cell 5"; cat "$TMP/s5.log"; FAILURES=$((FAILURES+1))
fi
wait || true

# --- Cell 6: our server (resumption)  <-  openssl s_client saving then resuming a session ---
echo "=== cell 6: our server (resumption)  <-  openssl s_client (-sess_out/-sess_in) ==="
P6=14506
# our server serves two connections over one STEK: it issues a ticket on the first and
# resumes it on the second (RFC 8446 4.6.1)
"$DRIVER" --role server --port $P6 --resume-count 1 --data-dir "$DATA_DIR" > "$TMP/s6.log" 2>&1 &
for _ in $(seq 1 100); do grep -q 'listening on' "$TMP/s6.log" && break; sleep 0.1; done
# connection 0: full handshake; hold open so the post-handshake NewSessionTicket arrives,
# then save the session (ticket) to disk
{ printf 'PING-6A\n'; sleep 2; } | "$OPENSSL" s_client -connect 127.0.0.1:$P6 -tls1_3 \
     -CAfile "$TMP/root.pem" -servername localhost -sess_out "$TMP/sess6.pem" \
     > "$TMP/c6a.out" 2>"$TMP/c6a.err" || true
# connection 1: resume with the saved session; openssl prints "Reused" iff our server
# accepted the ticket and resumed
{ printf 'PING-6B\n'; sleep 2; } | "$OPENSSL" s_client -connect 127.0.0.1:$P6 -tls1_3 \
     -CAfile "$TMP/root.pem" -servername localhost -sess_in "$TMP/sess6.pem" \
     > "$TMP/c6b.out" 2>"$TMP/c6b.err" || true
if grep -q 'PING-6B' "$TMP/c6b.out" && grep -qi 'Reused' "$TMP/c6b.out"; then
  echo "  PASS: our server issued a ticket and resumed it (openssl reports Reused)"
else
  echo "  FAIL: cell 6"; cat "$TMP/s6.log" "$TMP/c6b.err" "$TMP/c6b.out"; FAILURES=$((FAILURES+1))
fi
wait || true

# --- Cell 7: our server (stapled OCSP)  <-  openssl s_client -status (RFC 6066) ---
echo "=== cell 7: our server (stapled OCSP)  <-  openssl s_client -status ==="
# our server serves the leaf+issuer chain and staples a current Good OCSP response; the
# OCSP hierarchy's own root is the trust anchor here (a separate hierarchy from cell 1's)
OCSPROOTHEX="$(grep '^root_cert=' "$DATA_DIR/Certs/OcspStapling.txt" | cut -d= -f2)"
echo -n "$OCSPROOTHEX" | xxd -r -p > "$TMP/ocsp_root.der"
"$OPENSSL" x509 -inform DER -in "$TMP/ocsp_root.der" -outform PEM -out "$TMP/ocsp_root.pem"
P7=14507
"$DRIVER" --role server --port $P7 --ocsp-staple ocsp_good --data-dir "$DATA_DIR" \
  > "$TMP/s7.log" 2>&1 &
for _ in $(seq 1 100); do grep -q 'listening on' "$TMP/s7.log" && break; sleep 0.1; done
# -status makes s_client send status_request and print the stapled response it received
{ printf 'PING-CELL-7\n'; sleep 2; } | "$OPENSSL" s_client -connect 127.0.0.1:$P7 -tls1_3 \
     -status -CAfile "$TMP/ocsp_root.pem" -servername localhost \
     -verify_hostname localhost -verify_return_error > "$TMP/c7.out" 2>"$TMP/c7.err" || true
# require both the app-data echo (strict verify held) and a stapled successful OCSP response
if grep -q 'PING-CELL-7' "$TMP/c7.out" && \
   grep -q 'OCSP Response Status: successful' "$TMP/c7.out"; then
  echo "  PASS: handshake (strict verify) + a stapled successful OCSP response"
else
  echo "  FAIL: cell 7"; cat "$TMP/s7.log" "$TMP/c7.err" "$TMP/c7.out"; FAILURES=$((FAILURES+1))
fi
wait || true

# --- Cell 8: our client (TLS 1.2 resumption)  ->  openssl s_server ---
echo "=== cell 8: our client (TLS 1.2 resumption)  ->  openssl s_server ==="
# our client makes two connections over one session cache; the second resumes the first
# (RFC 5077 tickets). This exercises the ec_point_formats offer a strict server needs to
# negotiate ECDHE at all on the resumed ClientHello. The EC server cert from cell 2 is reused.
P8=14508
"$OPENSSL" s_server -cert "$TMP/srv_cert.pem" -key "$TMP/srv_key.pem" -tls1_2 \
  -accept $P8 -rev -naccept 2 > "$TMP/s8.log" 2>&1 &
for _ in $(seq 1 100); do grep -q 'ACCEPT' "$TMP/s8.log" && break; sleep 0.1; done
if "$DRIVER" --role client --port $P8 --host localhost --ca "$TMP/srv_cert.pem" \
     --resume-count 1 --message "hello-cell-8" --data-dir "$DATA_DIR"; then
  echo "  PASS: TLS 1.2 client resumption (two connections, the second resumed)"
else
  echo "  FAIL: cell 8"; cat "$TMP/s8.log"; FAILURES=$((FAILURES+1))
fi
wait || true

# --- PQ hybrid cells (X25519MLKEM768): version-gated on openssl >= 3.5 -------------
# These prove BOTH handshake shapes the single-key_share model produces against a real
# peer: direct (hybrid key_share first) and HRR-induced (classical key_share first, peer
# insists on the hybrid). They reuse cell 1's root.pem and cell 2's srv_cert/srv_key.
if [ "$HYBRID_OK" -eq 1 ]; then
  TOTAL=$((TOTAL+3))

  # --- Cell H1: our server  <-  openssl s_client -groups X25519MLKEM768 (direct) ---
  echo "=== cell H1: our server  <-  openssl s_client (X25519MLKEM768) ==="
  PH1=14591
  "$DRIVER" --role server --port $PH1 --groups X25519MLKEM768 --data-dir "$DATA_DIR" > "$TMP/sh1.log" 2>&1 &
  for _ in $(seq 1 100); do grep -q 'listening on' "$TMP/sh1.log" && break; sleep 0.1; done
  { printf 'PING-CELL-H1\n'; sleep 2; } | "$OPENSSL" s_client -connect 127.0.0.1:$PH1 -tls1_3 \
       -groups X25519MLKEM768 -CAfile "$TMP/root.pem" -servername localhost \
       -verify_hostname localhost -verify_return_error > "$TMP/ch1.out" 2>"$TMP/ch1.err" || true
  if grep -q 'PING-CELL-H1' "$TMP/ch1.out"; then
    echo "  PASS: our server selected X25519MLKEM768 (strict verify) + app-data echo"
  else
    echo "  FAIL: cell H1"; cat "$TMP/sh1.log" "$TMP/ch1.err"; FAILURES=$((FAILURES+1))
  fi
  wait || true

  # --- Cell H2: our client (direct)  ->  openssl s_server -groups X25519MLKEM768 ---
  echo "=== cell H2: our client (direct)  ->  openssl s_server (X25519MLKEM768) ==="
  PH2=14592
  "$OPENSSL" s_server -cert "$TMP/srv_cert.pem" -key "$TMP/srv_key.pem" -tls1_3 \
    -groups X25519MLKEM768 -accept $PH2 -rev -naccept 1 > "$TMP/sh2.log" 2>&1 &
  for _ in $(seq 1 100); do grep -q 'ACCEPT' "$TMP/sh2.log" && break; sleep 0.1; done
  # our client offers only the hybrid, so it key-shares it directly (no HRR)
  if "$DRIVER" --role client --port $PH2 --host localhost --ca "$TMP/srv_cert.pem" \
       --groups X25519MLKEM768 --message "hello-cell-h2" --data-dir "$DATA_DIR"; then
    echo "  PASS: our client key-shared the hybrid directly (no HRR) + app-data"
  else
    echo "  FAIL: cell H2"; cat "$TMP/sh2.log"; FAILURES=$((FAILURES+1))
  fi
  wait || true

  # --- Cell H3: our client (classical key_share first)  ->  hybrid-only s_server = HRR ---
  echo "=== cell H3: our client (HRR)  ->  openssl s_server (X25519MLKEM768) ==="
  PH3=14593
  "$OPENSSL" s_server -cert "$TMP/srv_cert.pem" -key "$TMP/srv_key.pem" -tls1_3 \
    -groups X25519MLKEM768 -accept $PH3 -rev -naccept 1 > "$TMP/sh3.log" 2>&1 &
  for _ in $(seq 1 100); do grep -q 'ACCEPT' "$TMP/sh3.log" && break; sleep 0.1; done
  # our client key-shares X25519 first but also offers the hybrid; the hybrid-only server
  # answers with a HelloRetryRequest for X25519MLKEM768 and the retried CH completes on it
  if "$DRIVER" --role client --port $PH3 --host localhost --ca "$TMP/srv_cert.pem" \
       --groups X25519,X25519MLKEM768 --message "hello-cell-h3" --data-dir "$DATA_DIR"; then
    echo "  PASS: HelloRetryRequest drove our client onto the hybrid + app-data"
  else
    echo "  FAIL: cell H3"; cat "$TMP/sh3.log"; FAILURES=$((FAILURES+1))
  fi
  wait || true
else
  echo "=== cells H1-H3 (X25519MLKEM768): SKIPPED (openssl < 3.5, 3 cells) ==="
fi

# --- ECH cells (RFC 9849): gated on an openssl that supports Encrypted Client Hello -----
# Prove ECH interop in BOTH directions against a real peer. One key pair openssl generates
# serves both sides: its PEM carries the HPKE private key (our server / openssl -ech_key) and
# the ECHConfigList (our client / openssl -ech_config_list). Each side asserts it saw ECH
# accepted - not a silent GREASE or shared-mode reject.
ECH_OK=0
if "$OPENSSL" s_client -help 2>&1 | grep -q 'ech_config_list' && \
   "$OPENSSL" s_server -help 2>&1 | grep -q 'ech_key'; then
  ECH_OK=1
fi
if [ "$ECH_OK" -eq 1 ]; then
  TOTAL=$((TOTAL+2))
  echo "ech:     supported (E-cells enabled)"
  "$OPENSSL" ech -public_name cover.example -out "$TMP/ech.pem" >/dev/null 2>&1
  # the base64 ECHConfigList is the ECHCONFIG PEM block body, flattened to one line
  awk '/-BEGIN ECHCONFIG-/{f=1;next} /-END ECHCONFIG-/{f=0} f' "$TMP/ech.pem" \
    | tr -d '\r\n' > "$TMP/echconfig.b64"

  # --- Cell E1: our server (ECH key store)  <-  openssl s_client (ECH) ---
  echo "=== cell E1: our server  <-  openssl s_client (ECH) ==="
  PE1=14571
  "$DRIVER" --role server --port $PE1 --ech-key "$TMP/ech.pem" --data-dir "$DATA_DIR" \
    > "$TMP/se1.log" 2>&1 &
  for _ in $(seq 1 100); do grep -q 'listening on' "$TMP/se1.log" && break; sleep 0.1; done
  # s_client sends ECH: the outer SNI is the public_name, the real (inner) SNI is localhost,
  # which our server recovers on a successful decrypt and serves the localhost cert for
  { printf 'PING-ECH-1\n'; sleep 2; } | "$OPENSSL" s_client -connect 127.0.0.1:$PE1 -tls1_3 \
       -ech_config_list "$(cat "$TMP/echconfig.b64")" -CAfile "$TMP/root.pem" \
       -servername localhost -verify_hostname localhost -verify_return_error \
       > "$TMP/ce1.out" 2>"$TMP/ce1.err" || true
  # require the app-data echo (strict verify against the inner name held) AND our server
  # reporting it accepted ECH (a shared-mode reject would have served no localhost cert)
  if grep -q 'PING-ECH-1' "$TMP/ce1.out" && grep -q 'ech-status: accepted' "$TMP/se1.log"; then
    echo "  PASS: our server accepted ECH + app-data echo (inner SNI recovered)"
  else
    echo "  FAIL: cell E1"; cat "$TMP/se1.log" "$TMP/ce1.err" "$TMP/ce1.out"; FAILURES=$((FAILURES+1))
  fi
  wait || true

  # --- Cell E2: our client (ECH)  ->  openssl s_server (ECH key) ---
  echo "=== cell E2: our client (ECH)  ->  openssl s_server ==="
  PE2=14572
  "$OPENSSL" s_server -cert "$TMP/srv_cert.pem" -key "$TMP/srv_key.pem" -tls1_3 \
    -ech_key "$TMP/ech.pem" -accept $PE2 -rev -naccept 1 > "$TMP/se2.log" 2>&1 &
  for _ in $(seq 1 100); do grep -q 'ACCEPT' "$TMP/se2.log" && break; sleep 0.1; done
  # our client seals the inner ClientHello (real SNI localhost) under the ECHConfigList; openssl
  # decrypts with the matching key and serves its localhost cert, which our client verifies
  if "$DRIVER" --role client --port $PE2 --host localhost --ca "$TMP/srv_cert.pem" \
       --ech-config "$TMP/echconfig.b64" --message "hello-ech-2" --data-dir "$DATA_DIR" \
       > "$TMP/ce2.out" 2>&1; then
    ECH2_OK=1
  else
    ECH2_OK=0
  fi
  if [ "$ECH2_OK" -eq 1 ] && grep -q 'ech-status: accepted' "$TMP/ce2.out"; then
    echo "  PASS: our client's ECH was accepted by openssl + app-data"
  else
    echo "  FAIL: cell E2"; cat "$TMP/se2.log" "$TMP/ce2.out"; FAILURES=$((FAILURES+1))
  fi
  wait || true
else
  echo "=== cells E1-E2 (ECH): SKIPPED (openssl without ECH support, 2 cells) ==="
fi

echo "=== openssl matrix: $((TOTAL-FAILURES))/$TOTAL cells passed ==="
[ "$FAILURES" -eq 0 ]
