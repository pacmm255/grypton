# Hard loopback benchmark

This benchmark is a deliberately difficult, black-box exercise for one Grypton
engagement. It combines an HTTP application, a separate newline-framed TCP
service, and a signed Android APK. It is intended to measure evidence-driven
web, network, and mobile-artifact testing without any source-code audit.

The benchmark binds only to loopback. The public manifest names the three
entrypoints and gives the binding scope. It does not disclose credentials,
signing material, expected findings, proof receipts, or the evaluator key.
Benchmark source, the evaluator sidecar, and anything outside the supplied
loopback services are out of scope.

Start a fresh instance in one terminal. Choose fixed ports when you want a
repeatable log location; omit them to have the operating system choose free
ports.

```bash
cd /root/grypton
bench=.state/benchmarks/courier-hard-01
./bin/grypton benchmark serve --out "$bench" --web-port 18777 --network-port 19001
```

The command writes `manifest.json`, a downloadable `courier.apk`, and a
sanitized event log beneath `$bench`. Keep that process running while Grypton
works. The manifest has the exact target, TCP endpoint, APK URL, scope entries,
and assessment brief. Use it to start a single multi-surface engagement:

```bash
target=$(jq -r '.engagement.target' "$bench/manifest.json")
scope=$(jq -r '.engagement.in_scope | join(",")' "$bench/manifest.json")
brief=$(jq -r '.engagement.brief' "$bench/manifest.json")

./bin/grypton init --force --target "$target" --type web \
  --in-scope "$scope" --max-turns 60 -m "$brief"
```

The worker has three benchmark-specific tools in addition to the normal
captured HTTP surface: `tcp_exchange` for a single scoped protocol frame,
`artifact_download` for the published APK, and `apk_inspect` /
`apk_extract_asset` for manifest, certificate, and binary-resource analysis.
They stay within the engagement workspace and retain evidence. APK bytecode and
manifest inspection are permitted; reading the lab's application source is not.

Score after the engagement is stopped. Pass the same target URL used for
`init`; Grypton derives its persistent workspace name from it.

```bash
./bin/grypton benchmark score "$bench/manifest.json" "$target" --json
```

Scoring requires both a benchmark proof receipt in a saved flow and the same
receipt in a durable `record_finding` entry. A response observed in a flow but
not recorded as a finding is shown as `observed_only`, so it does not inflate
the result. The report deliberately gives case identifiers and coverage rather
than an answer key.

The lab includes protected controls and ordinary-looking decoys. A positive
result must include a valid control, a cross-boundary or clone result, and the
saved capture that demonstrates impact. Treat it like a professional assessment:
avoid brute force, use the supplied test material, and keep all activity inside
the manifest scope.
