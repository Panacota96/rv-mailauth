"""Independent DKIM oracle: dkimpy re-verifies every DKIM signature of the sample evidence with the same public
keys and must agree with rv-mailauth's dkim.json, signature by signature (pass vs not pass).

    python tests/oracle_dkim.py <evidence dir> <dkim key file> <reports dir of a run>

Exit 0 = agreement, 1 = disagreement (listed), 77 = skipped (dkimpy not installed). dkimpy is a test-only
oracle (BSD-style licence) and never ships with the tool. The mbox split and un-escaping, the key-file parsing
and the mapping from reports to evidence are re-implemented here on purpose (no shared code with the tool).
"""
import json
import re
import sys
from pathlib import Path

try:
    import dkim
    import dkim.util
except ImportError:
    print("SKIP: dkimpy is not installed (pip install dkimpy pynacl)")
    sys.exit(77)


def load_keys(path: Path) -> dict:
    keys = {}
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        t = raw.strip()
        if not t or t[0] in "#;$":
            continue
        if "\t" in raw and not re.match(r"^\S+\s+(\d+\s+)?(IN\s+)?TXT\b", raw, re.I):
            name, value = raw.split("\t", 1)
        else:
            rec = raw
            if "(" in rec:
                while ")" not in rec and i < len(lines):
                    rec += " " + lines[i]
                    i += 1
            m = re.match(r"^(\S+)\s+(?:\d+\s+)?(?:IN\s+)?TXT\s+(.*)$", rec.replace("(", " ").replace(")", " "), re.I)
            if not m:
                continue
            name, value = m.group(1), m.group(2)
        quoted = re.findall(r'"((?:[^"\\]|\\.)*)"', value)
        value = "".join(quoted) if quoted else value.strip()
        keys[name.strip().rstrip(".").lower()] = value.strip()
    return keys


def split_mbox(data: bytes):
    """Messages of an mbox: a separator is a line starting with 'From ' at the start or after an empty line."""
    lines = data.split(b"\n")
    starts = []
    for n, line in enumerate(lines):
        if line.startswith(b"From ") and (n == 0 or lines[n - 1].rstrip(b"\r") == b""):
            starts.append(n)
    msgs = []
    for k, s in enumerate(starts):
        end = starts[k + 1] - 1 if k + 1 < len(starts) else len(lines)  # drop the blank line before the next
        body = b"\n".join(lines[s + 1:end])
        if k + 1 < len(starts):
            body += b"\n"
        out = []
        for ln in body.split(b"\n"):
            if re.match(rb"^>+From ", ln):
                ln = ln[1:]
            out.append(ln)
        msgs.append(b"\n".join(out))
    return msgs


def dkimpy_results(msg: bytes, keys: dict):
    def dnsfunc(name, timeout=5):
        n = name.decode() if isinstance(name, bytes) else name
        v = keys.get(n.rstrip(".").lower())
        return v.encode() if v else b""

    d = dkim.DKIM(msg)
    out = []
    sigs = [v for (k, v) in d.headers if k.lower() == b"dkim-signature"]
    for idx, value in enumerate(sigs):
        tags = dkim.util.parse_tag_value(b"".join(value.split()))
        try:
            ok = dkim.DKIM(msg).verify(idx=idx, dnsfunc=dnsfunc)
        except Exception:  # dkimpy raises on missing/invalid keys
            ok = False
        out.append((tags.get(b"d", b"").decode(), tags.get(b"s", b"").decode(), bool(ok)))
    return out


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    evidence, keyfile, reports = map(Path, sys.argv[1:])
    keys = load_keys(keyfile)
    # Ours: item folder -> (file name, dkim.json signatures)
    ours = {}
    for tech in sorted(reports.glob("items/*/technical.json")):
        t = json.loads(tech.read_text(encoding="utf-8"))
        name = t["item"]["file_name"]
        dj = tech.parent / "dkim.json"
        sigs = json.loads(dj.read_text(encoding="utf-8"))["dkim"]["signatures"] if dj.is_file() else None
        ours[re.sub(r"@\d+$", "", name)] = sigs
    problems = []
    checked = 0
    for f in sorted(evidence.iterdir()):
        data = f.read_bytes()
        if f.suffix == ".msg":
            sigs = ours.get(f.name) or []
            bad = [s for s in sigs if s["result"] != "not_evaluated"]
            if bad:
                problems.append(f"{f.name}: .msg signature evaluated ({bad[0]['result']}); the original body is not stored")
            continue
        targets = [(f.name, data)] if f.suffix != ".mbox" else [
            (f"{f.name}#{n}", m) for n, m in enumerate(split_mbox(data), 1)]
        for key, msg in targets:
            theirs = dkimpy_results(msg, keys)
            mine = ours.get(key)
            if mine is None:
                problems.append(f"{key}: no dkim.json in the reports")
                continue
            mine_pairs = [(s["domain"], s["selector"], s["result"] == "pass") for s in mine]
            if sorted(theirs) != sorted(mine_pairs):
                problems.append(f"{key}: dkimpy {theirs} != rv-mailauth {[(s['domain'], s['selector'], s['result']) for s in mine]}")
            for d, s, ok in theirs:
                checked += 1
                print(f"{key:40} d={d:22} s={s:8} dkimpy={'pass' if ok else 'fail':5} rv-mailauth="
                      f"{next((x['result'] for x in mine if x['domain'] == d and x['selector'] == s), '-')}")
    if problems:
        print("DISAGREEMENT:\n  " + "\n  ".join(problems))
        sys.exit(1)
    print(f"OK: dkimpy agrees with rv-mailauth on {checked} DKIM signature(s)")


if __name__ == "__main__":
    main()
