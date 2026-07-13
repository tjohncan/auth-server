# Fuzzing

Fuzzing feeds a function mutated inputs at high speed and watches, under a sanitizer,
for any input that crashes it or trips undefined behavior. You write a small harness that
hands one blob of bytes to one function; the fuzzer generates the blobs.

## Targets

| Target | Function | Surface |
|---|---|---|
| `http` | `http_request_parse` + accessors | Socket-facing request parser: in-place pointer arithmetic over attacker bytes. |
| `jwt`  | `jwt_decode_auth_request` | Authorization-code decoder: HMAC verify, base64url, hand-rolled JSON, hex decode. |

Each harness mirrors the real call path. `fuzz_http.c` follows
`main.c:router_request_handler()`: the same private NUL-terminated copy of the socket
bytes, the same parse call, the same accessors afterward. `fuzz_jwt.c` follows the
OAuth token-exchange path into `jwt_decode_auth_request()`. A harness that drifts from
the real call path fuzzes fiction, so keep them aligned when the callers change.

### A note on the JWT harness

`jwt_decode_auth_request()` verifies the HMAC signature before it parses the payload. A
token with a random signature is rejected at the gate and never reaches the JSON and hex
parsing that are the reason to fuzz it. So the harness holds a fixed secret, lets the
fuzzer author the *payload*, and signs a well-formed token around it — every input clears
the gate and reaches the parsers. This is the standard shape for fuzzing code behind a
signature check; in production only this server, verifying codes it minted itself, can put
bytes past that gate.

## Commands

| Command | Needs | Runtime | Purpose |
|---|---|---|---|
| `make fuzz-regress` | gcc | seconds | Replay every saved crash + seed under ASan/UBSan. Part of `make test`. |
| `make fuzz` | clang | `FUZZ_TIME` (default 60s) | Coverage-guided search for new bugs. |
| `make sanitize` | gcc | ~1 min | Build the whole server with ASan+UBSan to drive by hand. |

```sh
make fuzz                              # http target, 60s
make fuzz FUZZ_TARGET=jwt FUZZ_TIME=3600
make fuzz-regress                      # both targets, gcc, seconds
```

libFuzzer ships with clang and has no gcc equivalent, so the coverage-guided run needs
clang. `make fuzz-regress` needs only gcc, which is why it — not `make fuzz` — is the gate
wired into `make test`.

## Layout

```
test/fuzz/
  fuzz_http.c   fuzz_jwt.c   harnesses (each also builds -DFUZZ_STANDALONE to replay one input)
  http.dict     jwt.dict     libFuzzer token dictionaries
  run.sh        build + run a target to a time budget + print a report card
  corpus/<target>/   committed seed corpus, one file per input shape
  crashes/<target>/  committed regression seeds: inputs that once crashed the target
.fuzz-work/<target>/ gitignored scratch: libFuzzer's evolving corpus and last-run.log
```

Two flags in `run.sh` are load-bearing and easy to omit by hand:

- **`-fno-sanitize-recover=undefined`.** By default UBSan prints a diagnostic and keeps
  running, so libFuzzer never registers a crash and a run over genuinely undefined code
  still reports "clean." This makes UB abort like ASan.
- **`-dict=…`.** Without a dictionary the mutator rediscovers tokens like `Content-Length:`
  or `"client_id":"` one byte at a time and burns its budget in the reject paths. The
  dictionaries supply those tokens.

## Reading the report card

```
================ FUZZ REPORT CARD ================
  target:     http_request_parse + accessors
  duration:   3600s
  build:      ASan + UBSan (no-recover), libFuzzer
  coverage:   cov: 91 ft: 237 corp: 95/4397b
  number_of_executed_units: 1285830590
  average_exec_per_sec: 357075
  crashes:    0
  RESULT:     CLEAN
=================================================
```

- **`crashes: 0` / `RESULT: CLEAN`** — no input crashed the target or tripped UB.
- **`cov:`** is edges reached. Each target saturates within seconds and then holds flat;
  once it plateaus, further runtime buys depth on covered code, not new branches. A long
  run that holds coverage flat and finds nothing is the result you want.
- **`exec/s`** in the 100k+ range means the harness is healthy; a collapse usually means it
  started doing I/O or a large allocation per input.

A clean run is not a proof of correctness. It is reproducible evidence that a large number
of adversarial inputs do not corrupt memory — a claim anyone can re-check by re-running it.

## When a run finds something

libFuzzer stops, prints the sanitizer trace, and saves the reproducer to
`crashes/<target>/crash-<hash>`.

1. Read the trace bottom-up; the frame in `src/` nearest the top is the bug site.
2. Reproduce in isolation: `.fuzz-work/<target>/fuzz_<target> crashes/<target>/crash-<hash>`.
3. Fix the root cause, not the one input — the saved file is one witness of a class.
4. Rename it to describe the input (e.g. `01-header-line-without-colon`) and keep it. It is
   now a regression seed replayed by every `make test`.
5. Re-run `make fuzz` and confirm the crash is gone and nothing new replaced it.

To confirm a regression seed is a real test rather than a vacuous one, replay it against the
code from before the fix and watch the sanitizer fire:

```sh
git show <pre-fix-rev>:src/server/http.c > /tmp/http_old.c
gcc -std=c11 -g -O1 -Iinclude -fsanitize=address,undefined -fno-sanitize-recover=undefined \
    -DFUZZ_STANDALONE test/fuzz/fuzz_http.c /tmp/http_old.c src/util/str.c src/util/json.c \
    -lcrypto -o /tmp/replay-old
/tmp/replay-old test/fuzz/crashes/http/01-header-line-without-colon   # expect: sanitizer fires
```
