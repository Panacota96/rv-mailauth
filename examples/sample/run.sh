#!/usr/bin/env sh
# Runs the sample review and checks the result. Usage: examples/sample/run.sh [path-to-rv-mailauth]
# Output folder: examples/sample/out (or $RV_SAMPLE_OUT).
# Fails (non-zero exit) if the self-test, `analyze` or verify-log fails, if the exit code or the finding
# codes and status of any item differ from expected_findings.json, or if the tool's hash register
# (logs/<RUN-ID>/hashes.csv) differs from the independently computed expected_hashes.csv.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bin=${1:-rv-mailauth}
out=${RV_SAMPLE_OUT:-"$here/out"}
expected="$here/expected_findings.json"
"$bin" self-test
"$bin" keys show "$here/dkim-keys.txt"
# The options of expected_findings.json ("args"): the sample public keys and "our" organisation's domain.
# Expected exit code 3: the sample set contains tampered messages (high findings); 0-3 are completed runs.
rc=0
"$bin" analyze --input "$here/evidence" --hash sha256,md5 --lang all --case DEMO-001 --actor "Sample" \
  --out "$out" --progress none --dkim-keys "$here/dkim-keys.txt" --own-domain acme.example || rc=$?
want_rc=$(sed -n 's/^  "exit_code": \([0-9]*\),*$/\1/p' "$expected")
if [ "$rc" != "$want_rc" ]; then
  echo "MISMATCH: analyze exited with $rc, expected_findings.json says $want_rc"
  exit 3
fi
run=$(ls "$out/logs" | tail -n 1)
"$bin" verify-log "$out/logs/$run"
# Compare every item of statistics.json (findings, status) with expected_findings.json ("files", "status").
# Both are pretty-printed JSON with one value per line; mbox messages are <mbox>#<n>@<offset> in the
# report and <mbox>#<n> in the expectations.
awk '
  function sorted(s,   n, a, i, j, t, r) {
    n = split(s, a, " "); r = ""
    for (i = 2; i <= n; i++) { t = a[i]; for (j = i - 1; j > 0 && a[j] > t; j--) a[j + 1] = a[j]; a[j + 1] = t }
    for (i = 1; i <= n; i++) r = r (i > 1 ? " " : "") a[i]
    return r
  }
  function str(line) { sub(/^[^"]*"/, "", line); sub(/".*$/, "", line); return line }
  FNR == 1 { f++ }
  f == 1 && /^  "files": \{/ { sec = "files"; next }
  f == 1 && /^  "status": \{/ { sec = "status"; next }
  f == 1 && /^  [}]/ { sec = ""; next }
  f == 1 && sec == "files" && /^    "/ { name = str($0); want[name] = ""; next }
  f == 1 && sec == "files" && /^      "/ { want[name] = want[name] (want[name] == "" ? "" : " ") str($0); next }
  f == 1 && sec == "status" && /^    "/ { v = $0; sub(/^[^:]*: "/, "", v); sub(/".*$/, "", v); wst[str($0)] = v; n++; next }
  f == 2 && /^      "findings": \[\]/ { codes = ""; next }
  f == 2 && /^      "findings": \[/ { codes = ""; inf = 1; next }
  f == 2 && inf && /^      \]/ { inf = 0; next }
  f == 2 && inf { codes = codes (codes == "" ? "" : " ") str($0); next }
  f == 2 && /^      "path": / { p = $0; sub(/^      "path": "/, "", p); sub(/",?$/, "", p); sub(/.*[\/\\]/, "", p); sub(/@[0-9]+$/, "", p); next }
  f == 2 && /^      "status": / {
    v = $0; sub(/^[^:]*: "/, "", v); sub(/".*$/, "", v); m++
    if (!(p in wst)) { print "MISMATCH: " p " is not in expected_findings.json"; bad = 1; next }
    if (sorted(codes) != want[p] || v != wst[p]) { print "MISMATCH " p ": tool [" sorted(codes) "] " v ", expected [" want[p] "] " wst[p]; bad = 1 }
  }
  END {
    if (m != n) { print "MISMATCH: the run has " m " items, expected_findings.json lists " n; bad = 1 }
    if (bad) exit 3
    print "findings and status match expected_findings.json (" n " items)"
  }' "$expected" "$out/reports/$run/statistics.json"
# Compare the tool's hash register with expected_hashes.csv: same files, sizes, SHA-256 and MD5.
# hashes.csv: index,path,size,<algorithms>,status,error (path may be quoted); fields are read from the right.
# Messages of an mbox are listed after it as <mbox>#<n>@<offset> (parts of a file, not files): skipped here.
awk -F, '
  FNR == 1 { if (FILENAME ~ /expected_hashes\.csv$/) { for (i = 1; i <= NF; i++) e[$i] = i } else { for (i = 1; i <= NF; i++) h[$i] = i; hn = NF }; next }
  FILENAME ~ /expected_hashes\.csv$/ { want[$e["file"]] = $e["size"] "," $e["sha256"] "," $e["md5"]; n++; next }
  {
    path = $0; sub(/^[0-9]+,/, "", path); sub(/,[0-9]+,[^,]*,[^,]*,[^,]*,[^,]*$/, "", path)
    gsub(/"/, "", path); sub(/.*[\/\\]/, "", path)
    if (path ~ /#[0-9]+@[0-9]+$/) next
    got[path] = $(NF - hn + h["size"]) "," $(NF - hn + h["sha256"]) "," $(NF - hn + h["md5"])
    m++
  }
  END {
    for (f in want) if (got[f] != want[f]) { print "MISMATCH " f ": tool " got[f] ", expected " want[f]; bad = 1 }
    if (m != n) { print "MISMATCH: the tool hashed " m " files, expected_hashes.csv lists " n; bad = 1 }
    if (bad) exit 3
    print "hashes.csv matches expected_hashes.csv (" n " files: size, SHA-256, MD5)"
  }' "$here/expected_hashes.csv" "$out/logs/$run/hashes.csv"
echo "Reports: $out/reports/$run/statistics.en.html"
