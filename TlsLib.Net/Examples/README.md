# TlsLib.Net examples

## RealPeerRevocationProbe

A network-gated live-revocation cell, not part of the unit harness. It handshakes with
`revoked.badssl.com` and `badssl.com` to capture the chain each presents, then runs the real
`TSocketHttpFetcher` + `TLiveRevocationChecker` stack against their live CRL endpoints and asserts
that the revoked certificate comes back Revoked and the good one Good. The chains are captured at
run time, so a certificate reissue cannot stale it.

Sources: `src/RealPeerRevocationProbeExample.pas`, with the Delphi program in
`Delphi/RealPeerRevocationProbe.dpr` and the Lazarus program in `Lazarus/RealPeerRevocationProbe.lpi`.
It needs outbound TLS and HTTP and exits 0 (PASS), 1 (FAIL) or 2 (a host cannot be reached).
