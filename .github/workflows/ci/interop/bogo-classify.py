#!/usr/bin/env python3
# Classifies a BoGo hard-gate run and prints the coverage boundary; non-zero on any
# unexpected result. Driven by run-bogo.sh.
#
#   bogo-classify.py audit-globs <config.json>
#       -> the [policy-difference] globs FORCE-RUN each gate to re-confirm the disable still
#          holds, ';'-joined. ([deferred]/[out-of-scope] are NOT force-run: an unsupported
#          scheme passes a negative test spuriously, which would be a false STALE.)
#   bogo-classify.py gate <config.json> <gate.json> <audit.json>
#       -> boundary; exit 1 on a FAIL, in-scope UNIMPLEMENTED, a stale/dead policy disable, a
#          fail-open hidden behind a disabled negative test, a disable glob that over-matches a
#          test that still ran, or an interrupted/incomplete run. bogo-shim-config.json is the
#          sole exclusion source.

import json
import os
import re
import sys
from fnmatch import fnmatchcase

BUCKETS = ("[out-of-scope]", "[policy-difference]", "[deferred]")
# Only [policy-difference] is FORCE-RUN in the audit to re-confirm the disable still holds. A
# policy-difference is a still-REJECTED handshake that only differs in the alert, so a force-run
# PASS genuinely means the difference is gone (stale). [deferred] and [out-of-scope] are NOT
# force-run: a deferred/unsupported scheme force-run tends to PASS spuriously (rejecting a scheme
# we do not implement coincidentally satisfies a negative test - e.g. ML-DSA / Kyber / an SCT on
# a TLS1.0 leg), which would be a false STALE. Their dead/stale detection cannot use force-run;
# the all-bucket over-match check below covers them without running anything.
FORCE_RUN_BUCKETS = ("[policy-difference]",)

# For a MUST-REJECT negative test (config "FailOpenGuarded"), a valid disable is a still-
# REJECTED handshake that merely differs in the alert/detail - BoGo reports that as "unexpected
# error". "unexpected success" means the shim ACCEPTED what it must reject (an auth/parse fail-
# open); "unexpected failure" means it BROKE a handshake it must complete. Either is a real
# regression a disable must never hide. (BoGo runner.go emits exactly these prefixes.)
#
# This check is SCOPED to FailOpenGuarded because "unexpected success" is EXPECTED for the many
# permissive policy differences where we intentionally accept what BoringSSL declines (ed25519 /
# P-521 / ignored legacy_record_version, all RFC-permitted) - flagging those would be wrong.
_FAIL_OPEN_PREFIXES = ("unexpected success", "unexpected failure")

# TLS 1.0/1.1 are deprecated (RFC 8996) and not built. A failing test whose name carries
# a TLS1/TLS11 version token but NO modern (TLS12/TLS13) token is a genuine old-version
# test - out of scope. Outcome-aware and modern-token-aware: a passing test is never
# touched, and a modern-version test that fails still surfaces (so real bugs are not
# hidden behind an old-version token used only as a min/mismatch operand).
_OLD_VER = re.compile(r"TLS1(1)?(?![0-9])")
_MODERN_VER = re.compile(r"TLS1[23](?![0-9])")


def is_old_version(name):
    return bool(_OLD_VER.search(name)) and not _MODERN_VER.search(name)


def load_config(config_path):
    return json.load(open(config_path, encoding="utf-8"))


def load_disabled(config_path):
    return load_config(config_path).get("DisabledTests", {})


def globs_for(disabled, *tags):
    return [g for g, r in disabled.items() if any(r.startswith(t) for t in tags)]


def load_run(path):
    # the whole BoGo result doc: {version, interrupted, tests, num_failures_by_type, ...},
    # or {} if the file is missing/corrupt (itself a truncation signal).
    try:
        return json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def load_tests(path):
    # {name: result}, each result a dict with actual / expected / is_unexpected / error
    # (see testresult.go). Returning the whole dict keeps the error string for the fail-open check.
    return load_run(path).get("tests", {})


def actual(result):
    return result.get("actual", "")


def is_fail_open(result):
    # the shim did not properly reject a negative test (or broke a positive one)
    return actual(result) == "FAIL" and \
        result.get("error", "").lstrip().startswith(_FAIL_OPEN_PREFIXES)


def matches_any(name, globs):
    return any(fnmatchcase(name, g) for g in globs)


def cmd_audit_globs(config_path):
    print(";".join(globs_for(load_disabled(config_path), *FORCE_RUN_BUCKETS)))
    return 0


def cmd_gate(config_path, gate_path, audit_path):
    cfg = load_config(config_path)
    disabled = cfg.get("DisabledTests", {})
    fail_open_guard = cfg.get("FailOpenGuarded", [])
    out_of_scope = globs_for(disabled, "[out-of-scope]")
    policy = globs_for(disabled, "[policy-difference]")
    deferred = globs_for(disabled, "[deferred]")
    force_run = globs_for(disabled, *FORCE_RUN_BUCKETS)  # policy + deferred
    untagged = [g for g in disabled if not any(disabled[g].startswith(t) for t in BUCKETS)]

    gate_run = load_run(gate_path)
    gate = gate_run.get("tests", {})
    audit = load_tests(audit_path)
    # BoGo sets interrupted=True when the run was cut short (signal / abort) - a precise
    # truncation signal that needs no magic count. A missing/corrupt file loads as {} -> True.
    interrupted = bool(gate_run.get("interrupted", True))

    passed = sorted(n for n, r in gate.items() if actual(r) == "PASS")
    # genuine TLS 1.0/1.1 tests that failed/were-skipped are out of scope (not unexpected)
    old_version = sorted(n for n, r in gate.items()
                         if actual(r) in ("FAIL", "SKIP") and is_old_version(n))
    old_set = set(old_version)
    failed = sorted(n for n, r in gate.items() if actual(r) == "FAIL" and n not in old_set)
    # no -allow-unimplemented on the gate pass, so an unimplemented in-scope test is a SKIP
    unimplemented = sorted(n for n, r in gate.items()
                           if actual(r) == "SKIP" and n not in old_set)

    # stale: a force-run disable (policy OR deferred) that now PASSES (its reason is gone)
    stale = sorted(n for n, r in audit.items()
                   if actual(r) == "PASS" and matches_any(n, force_run))
    # dead: a force-run glob that matched no force-run test (renamed/removed test)
    dead = sorted(g for g in force_run if not any(matches_any(n, [g]) for n in audit))
    # fail-open hidden behind a disabled MUST-REJECT negative (FailOpenGuarded): force-run and
    # the shim did not reject (handshake completed / a positive broke). A disable must never mask
    # this. Scoped to the guarded globs so a permissive policy difference is not mis-flagged.
    fail_open = sorted(n for n, r in audit.items()
                       if is_fail_open(r) and matches_any(n, fail_open_guard))
    # over-match: a disable glob (ANY bucket) that matches a test which nonetheless PASSED in
    # the gate. A disabled test is excluded from the run, so this means the ledger's glob and
    # the runner's matcher disagree - the disable is not taking effect / is mis-scoped.
    over_match = sorted(n for n in passed if matches_any(n, list(disabled)))

    print("")
    print("================= BoGo hard-gate coverage boundary =================")
    workers = os.environ.get("BOGO_WORKERS", "1")
    print(f"  peer-pinned full-suite run; -num-workers {workers}"
          + ("" if workers == "1" else " (parallel; verdict is worker-count-independent)"))
    print(f"  PASS (in-scope, required): {len(passed)}")
    print(f"  DISABLED ledger: {len(disabled)} globs "
          f"-> out-of-scope {len(out_of_scope)}, "
          f"policy-difference {len(policy)}, deferred {len(deferred)}")
    print(f"  DISABLED old TLS 1.0/1.1 (RFC 8996, by rule): {len(old_version)}")
    print(f"  policy-difference disables force-run this gate: "
          f"{sum(1 for n in audit)} re-confirmed still-differ")
    print("  NOTE: [deferred]/[out-of-scope] globs are NOT force-run (an unsupported scheme "
          "passes a negative test spuriously); a fully-dead one is not auto-detected (no test list).")
    print("--------------------------------------------------------------------")
    print(f"  UNEXPECTED - regression FAIL:            {len(failed)}")
    print(f"  UNEXPECTED - in-scope UNIMPLEMENTED:     {len(unimplemented)}")
    print(f"  UNEXPECTED - STALE disable (now passes): {len(stale)}")
    print(f"  UNEXPECTED - DEAD glob (matches nothing):{len(dead)}")
    print(f"  UNEXPECTED - FAIL-OPEN behind a disable: {len(fail_open)}")
    print(f"  UNEXPECTED - disable over-matches a run: {len(over_match)}")
    print(f"  UNEXPECTED - run interrupted / incomplete:{'yes' if interrupted else 'no'}")
    if untagged:
        print(f"  WARNING - untagged disable glob(s): {len(untagged)} (bucket them)")

    def dump(title, names, hint):
        if not names:
            return
        print(f"\n  >>> {title} ({len(names)}) - {hint}:")
        for n in names:
            print(f"      {n}")

    dump("regression FAIL", failed, "fix the library (or, if a defensible policy, add a [policy-difference] disable)")
    dump("in-scope UNIMPLEMENTED", unimplemented,
         "add shim support to make it PASS, or bucket it in the disable ledger")
    dump("STALE disable", stale, "the difference is gone; promote to PASS / remove the disable")
    dump("DEAD glob", dead, "the test was renamed/removed; update or drop the glob")
    dump("FAIL-OPEN behind a disable", fail_open,
         "the shim accepted what it must reject (or broke a positive) - a real regression the "
         "disable was hiding; fix the library")
    dump("disable over-matches a run", over_match,
         "the glob matches a test that still ran+passed; tighten the glob (ledger/runner "
         "matcher disagreement)")

    unexpected = (len(failed) + len(unimplemented) + len(stale) + len(dead)
                  + len(fail_open) + len(over_match) + (1 if interrupted else 0))
    print("--------------------------------------------------------------------")
    if interrupted:
        print("  INTERRUPTED: BoGo marked the run interrupted (or the result file was "
              "missing/corrupt) - it did not complete; treat every result as unreliable.")
    if unexpected == 0 and not untagged:
        print("  RESULT: PASS - every test passed or is an accounted-for disable.")
        print("====================================================================")
        return 0
    print(f"  RESULT: FAIL - {unexpected} unexpected result(s). Triage each into the")
    print("          disable ledger (pass/fix, or bucket with a reason) - the gate")
    print("          working, not noise.")
    print("====================================================================")
    return 1


def main(argv):
    if len(argv) >= 3 and argv[1] == "audit-globs":
        return cmd_audit_globs(argv[2])
    if len(argv) >= 5 and argv[1] == "gate":
        return cmd_gate(argv[2], argv[3], argv[4])
    sys.stderr.write(
        "usage: bogo-classify.py audit-globs <config.json>\n"
        "       bogo-classify.py gate <config.json> <gate.json> <audit.json>\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
