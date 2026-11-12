"""Generates the synthetic sample evidence of rv-mailauth (examples/sample).

    python tests/make_samples.py            (from the repository root; needs dkimpy, pynacl, cryptography,
                                             blake3, and cargo for the .msg samples)

What it writes:
  examples/sample/evidence/*.eml|*.msg|*.mbox   synthetic messages (example.org / example.net / acme.example,
                                                 IBAN test numbers from the ISO 13616 documentation)
  examples/sample/dkim-keys.txt                  the PUBLIC keys only (simple and BIND forms)
  examples/sample/expected_findings.json         ground truth, written from the construction below
  examples/sample/expected_hashes.csv            md5, sha1, sha256, sha512, sha3-256, blake3 (hashlib/blake3)

Every private key is generated in memory for this run, used to sign, and discarded: none is written to disk,
printed or logged. Re-running therefore produces new keys, new signatures and new hashes; commit the whole
output together.
"""
import base64
import csv
import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path

import blake3
import dkim
import nacl.signing
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "sample"
EV = SAMPLE / "evidence"
OWN = ["acme.example"]
CRLF = "\r\n"


# ---------------------------------------------------------------- keys (private parts stay in memory)

class RsaKey:
    def __init__(self):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())
        der = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.txt = "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()

    def sign(self, msg: bytes, selector: str, domain: str, canon=(b"relaxed", b"relaxed")) -> bytes:
        return dkim.sign(msg, selector.encode(), domain.encode(), self._pem, canonicalize=canon)


class EdKey:
    def __init__(self):
        k = nacl.signing.SigningKey.generate()
        self._seed = base64.b64encode(bytes(k))
        self.txt = "v=DKIM1; k=ed25519; p=" + base64.b64encode(bytes(k.verify_key)).decode()

    def sign(self, msg: bytes, selector: str, domain: str, canon=(b"relaxed", b"simple")) -> bytes:
        return dkim.sign(msg, selector.encode(), domain.encode(), self._seed, canonicalize=canon,
                         signature_algorithm=b"ed25519-sha256")


# Severity of each code (independent copy of the tool's table) → expected item status and run exit code.
HIGH = {"DKIM_BODY_HASH_MISMATCH"}
INFO = {"DKIM_KEY_NOT_AVAILABLE", "PAYMENT_DETAILS_MENTIONED", "DKIM_SIGNATURE_VALID", "AUTH_RESULTS_RECORDED"}


def status_of(codes):
    if any(c in HIGH for c in codes):
        return "problem"
    return "attention" if any(c not in INFO for c in codes) else "ok"


def with_status(out: dict) -> dict:
    out["status"] = {k: status_of(v) for k, v in out["files"].items()}
    out["exit_code"] = 3 if "problem" in out["status"].values() else 0
    return out


def build(headers, body: str) -> bytes:
    text = CRLF.join(headers) + CRLF + CRLF + body.replace("\r\n", "\n").replace("\n", CRLF)
    if not text.endswith(CRLF):
        text += CRLF
    return text.encode("utf-8")


def prepend(headers, msg: bytes) -> bytes:
    return (CRLF.join(headers) + CRLF).encode("utf-8") + msg


def core(subject, date, mid, body, frm="Bruno Proveedor <bruno@example.org>", extra=(), first_hop=None):
    hop = first_hop or ("Received: from [192.0.2.10] (laptop.example.org) by smtp.example.org with ESMTPSA id 77B1 "
                        "for <ana@acme.example>; " + date)
    return build([hop, "From: " + frm, "To: Ana Compras <ana@acme.example>", "Subject: " + subject,
                  "Date: " + date, "Message-ID: " + mid, *extra, "MIME-Version: 1.0",
                  "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: 8bit"], body)


def delivered(msg: bytes, at: str, ar=None) -> bytes:
    """What the receiving server adds on top: its Received hop, Authentication-Results, Return-Path."""
    top = ["Return-Path: <bruno@example.org>",
           "Received: from smtp.example.org (smtp.example.org [192.0.2.25]) by mx.acme.example with ESMTPS id 4F2A1; " + at]
    if ar:
        top.append("Authentication-Results: mx.acme.example; " + ar)
    return prepend(top, msg)


def make_msg(path: Path, spec: dict):
    r = subprocess.run(["cargo", "run", "-q", "-p", "rv-mailauth-core", "--example", "make_msg", "--", str(path)],
                       input=json.dumps(spec).encode(), cwd=ROOT, capture_output=True)
    if r.returncode != 0:
        sys.exit("make_msg failed: " + r.stderr.decode(errors="replace"))


def main():
    EV.mkdir(parents=True, exist_ok=True)
    for old in EV.iterdir():
        if old.is_file():
            old.unlink()
    k2026, ked, k2025_old, k2025_new, kmailer, k2019 = RsaKey(), EdKey(), RsaKey(), RsaKey(), RsaKey(), RsaKey()
    expected = {}
    files = {}

    def save(name, data, codes):
        files[name] = data
        expected[name] = sorted(codes)

    d1 = "Tue, 10 Nov 2026 09:00:00 +0100"
    hop_at = "Tue, 10 Nov 2026 08:00:04 +0000"

    # 01 clean, RSA, with the receiving server's Authentication-Results.
    m = core("Acta de la reunión de noviembre", d1, "<20261110090000.1@example.org>",
             "Hola Ana,\n\nadjunto el acta de la reunión del lunes.\n\nSaludos,\nBruno\n")
    m = k2026.sign(m, "s2026", "example.org") + m
    save("01-clean-rsa.eml", delivered(m, hop_at, "dkim=pass header.d=example.org header.s=s2026; spf=pass smtp.mailfrom=example.org"),
         ["DKIM_SIGNATURE_VALID", "AUTH_RESULTS_RECORDED"])

    # 02 clean, Ed25519 (relaxed/simple).
    d2 = "Tue, 10 Nov 2026 10:15:00 +0100"
    m = core("Compte rendu", d2, "<20261110101500.2@example.org>",
             "Bonjour Ana,\n\nvoici le compte rendu de la réunion.\n\nCordialement,\nBruno\n")
    m = ked.sign(m, "ed2026", "example.org") + m
    save("02-clean-ed25519.eml", delivered(m, "Tue, 10 Nov 2026 09:15:03 +0000"), ["DKIM_SIGNATURE_VALID"])

    # 03 body edited after signing (the amount).
    d3 = "Tue, 10 Nov 2026 11:00:00 +0100"
    m = core("Pedido 4411", d3, "<20261110110000.3@example.org>",
             "Ana,\n\nconfirmo el pedido 4411 por un importe de 1.200 EUR.\n\nBruno\n")
    m = k2026.sign(m, "s2026", "example.org") + m
    m = m.replace(b"1.200 EUR", b"12.000 EUR")
    save("03-body-edited.eml", delivered(m, "Tue, 10 Nov 2026 10:00:02 +0000"), ["DKIM_BODY_HASH_MISMATCH"])

    # 04 signed header edited after signing (the Subject).
    d4 = "Tue, 10 Nov 2026 11:30:00 +0100"
    m = core("Entrega del lote 7", d4, "<20261110113000.4@example.org>",
             "Ana,\n\nel lote 7 sale el jueves.\n\nBruno\n")
    m = k2026.sign(m, "s2026", "example.org") + m
    m = m.replace(b"Subject: Entrega del lote 7", b"Subject: Entrega del lote 9")
    save("04-header-edited.eml", delivered(m, "Tue, 10 Nov 2026 10:30:01 +0000"), ["DKIM_SIGNATURE_INVALID"])

    # 05 genuine message signed with a key that was rotated since: the key file holds only the new key.
    d5 = "Mon, 12 Oct 2026 16:00:00 +0200"
    m = core("Calendario de entregas", d5, "<20261012160000.5@example.org>",
             "Ana,\n\nte envío el calendario de entregas de octubre.\n\nBruno\n")
    m = k2025_old.sign(m, "s2025", "example.org") + m
    save("05-rotated-key.eml", delivered(m, "Mon, 12 Oct 2026 14:00:03 +0000"), ["DKIM_SIGNATURE_INVALID"])

    # 06 lookalike domain (rn instead of m), unsigned.
    d6 = "Wed, 11 Nov 2026 08:10:00 +0000"
    m = build(["Return-Path: <tesoreria@acrne.example>",
               "Received: from mail.acrne.example (mail.acrne.example [198.51.100.7]) by mx.acme.example with ESMTP id 9C01; Wed, 11 Nov 2026 08:10:06 +0000",
               "From: Tesorería <tesoreria@acrne.example>", "To: Ana Compras <ana@acme.example>",
               "Subject: Factura pendiente", "Date: " + d6, "Message-ID: <a1@acrne.example>",
               "Content-Type: text/plain; charset=utf-8"],
              "Ana,\n\nnecesitamos que revises la factura pendiente hoy.\n\nTesorería\n")
    save("06-lookalike-domain.eml", m, ["LOOKALIKE_DOMAIN", "DKIM_NOT_SIGNED"])

    # 07 Reply-To pointing to another organisation, valid signature.
    d7 = "Wed, 11 Nov 2026 09:00:00 +0100"
    m = core("Cambio de contacto", d7, "<20261111090000.7@example.org>",
             "Ana,\n\npor favor responde a mi nueva dirección.\n\nBruno\n",
             extra=("Reply-To: Bruno <bruno.proveedor@example.net>",))
    m = k2026.sign(m, "s2026", "example.org") + m
    save("07-reply-to-trap.eml", delivered(m, "Wed, 11 Nov 2026 08:00:03 +0000"), ["DKIM_SIGNATURE_VALID", "REPLY_TO_DIFFERS"])

    # 08 display name with the own organisation's name, external address, unsigned.
    d8 = "Wed, 11 Nov 2026 10:00:00 +0000"
    m = build(["Received: from relay.example.net (relay.example.net [203.0.113.9]) by mx.acme.example with ESMTP id 5D3E; Wed, 11 Nov 2026 10:00:05 +0000",
               "From: ACME - Dirección Financiera <direccion.financiera@example.net>",
               "To: Ana Compras <ana@acme.example>", "Subject: Pago urgente", "Date: " + d8,
               "Message-ID: <d8@example.net>", "Content-Type: text/plain; charset=utf-8"],
              "Ana,\n\nnecesito que hagas un pago hoy, te paso los detalles luego.\n")
    save("08-display-name-spoof.eml", m, ["DISPLAY_NAME_SPOOF", "DKIM_NOT_SIGNED"])

    # 09 payment details changed (EN/ES/FR wording, IBAN test number), valid signature.
    d9 = "Wed, 11 Nov 2026 11:00:00 +0100"
    m = core("Updated payment information", d9, "<20261111110000.9@example.org>",
             "Dear Ana,\n\nplease note that our bank details have changed.\nNew IBAN: DE89 3704 0044 0532 0130 00\n\n"
             "Nuevos datos bancarios / nouvelles coordonnées bancaires ci-dessus.\n\nBruno\n")
    m = k2026.sign(m, "s2026", "example.org") + m
    save("09-payment-details.eml", delivered(m, "Wed, 11 Nov 2026 10:00:02 +0000"), ["DKIM_SIGNATURE_VALID", "PAYMENT_DETAILS_MENTIONED"])

    # 10 .msg with transport headers (taken from a signed, delivered message).
    d10 = "Thu, 12 Nov 2026 09:00:00 +0100"
    m = core("Contrato firmado", d10, "<20261112090000.10@example.org>", "Ana,\n\nadjunto el contrato.\n\nBruno\n")
    m = k2026.sign(m, "s2026", "example.org") + m
    m = delivered(m, "Thu, 12 Nov 2026 08:00:04 +0000", "dkim=pass header.d=example.org; spf=pass smtp.mailfrom=example.org")
    th = m.split(b"\r\n\r\n", 1)[0].decode() + CRLF
    pdf = base64.b64encode(b"%PDF-1.4\n% synthetic sample, not a real contract\n%%EOF\n").decode()
    make_msg(EV / "10-transport-headers.msg", {
        "subject": "Contrato firmado", "sender_name": "Bruno Proveedor", "sender_email": "bruno@example.org",
        "body": "Ana,\r\n\r\nadjunto el contrato.\r\n\r\nBruno\r\n", "message_id": "<20261112090000.10@example.org>",
        "submit_time": 1794470400, "delivery_time": 1794470404, "transport_headers": th,
        "attachments": [{"name": "contrato.pdf", "mime": "application/pdf", "data_b64": pdf, "modified": 1794466800}]})
    expected["10-transport-headers.msg"] = sorted(["DKIM_SIGNATURE_NOT_EVALUATED", "AUTH_RESULTS_RECORDED"])

    # 11 .msg without transport headers (e.g. a saved sent item).
    make_msg(EV / "11-no-transport-headers.msg", {
        "subject": "Borrador de propuesta", "sender_name": "Bruno Proveedor", "sender_email": "bruno@example.org",
        "body": "Propuesta preliminar.\r\n", "message_id": "<20261112100000.11@example.org>",
        "submit_time": 1794474000, "transport_headers": None, "attachments": []})
    expected["11-no-transport-headers.msg"] = ["MSG_TRANSPORT_HEADERS_MISSING"]

    # 12 mbox with three messages: clean (with a body line that needs "From " escaping), tampered, bad dates.
    mb1 = core("Albarán 31", "Wed, 11 Nov 2026 12:00:00 +0100", "<20261111120000.12@example.org>",
               "Ana,\n\nFrom the warehouse: the delivery note is attached below.\n\nBruno\n")
    mb1 = k2026.sign(mb1, "s2026", "example.org") + mb1
    mb1 = delivered(mb1, "Wed, 11 Nov 2026 11:00:03 +0000")
    mb2 = core("Albarán 32", "Wed, 11 Nov 2026 12:30:00 +0100", "<20261111123000.13@example.org>",
               "Ana,\n\nson 40 cajas.\n\nBruno\n")
    mb2 = k2026.sign(mb2, "s2026", "example.org") + mb2
    mb2 = delivered(mb2, "Wed, 11 Nov 2026 11:30:02 +0000").replace(b"son 40 cajas", b"son 4 cajas")
    mb3 = build(["Received: from smtp.example.org (smtp.example.org [192.0.2.25]) by mx.acme.example with ESMTPS id 6A; Wed, 11 Nov 2026 09:40:00 +0000",
                 "Received: from [192.0.2.30] by smtp.example.org with ESMTPSA id 6B; Wed, 11 Nov 2026 10:00:00 +0000",
                 "From: Bruno Proveedor <bruno@example.org>", "To: Ana Compras <ana@acme.example>",
                 "Subject: Albarán 33", "Date: Wed, 11 Nov 2026 16:30:00 +0500",
                 "Message-ID: <x33@mailer.example.com>", "Content-Type: text/plain; charset=utf-8"],
                "Ana,\n\nalbarán 33.\n\nBruno\n")
    mbox = io.BytesIO()
    for i, (frm_line, msg) in enumerate([("From bruno@example.org Wed Nov 11 11:00:03 2026", mb1),
                                         ("From bruno@example.org Wed Nov 11 11:30:02 2026", mb2),
                                         ("From bruno@example.org Wed Nov 11 09:40:00 2026", mb3)]):
        mbox.write(frm_line.encode() + b"\r\n")
        for line in msg.split(b"\r\n")[:-1]:
            if line.lstrip(b">").startswith(b"From "):  # mboxrd escaping
                line = b">" + line
            mbox.write(line + b"\r\n")
        mbox.write(b"\r\n")
    assert b"\r\n>From the warehouse" in mbox.getvalue()
    save("12-mailbox.mbox", mbox.getvalue(), [])
    expected["12-mailbox.mbox#1"] = ["DKIM_SIGNATURE_VALID"]
    expected["12-mailbox.mbox#2"] = ["DKIM_BODY_HASH_MISMATCH"]
    expected["12-mailbox.mbox#3"] = sorted(["DKIM_NOT_SIGNED", "RECEIVED_TIME_NOT_MONOTONIC", "DATE_AFTER_FIRST_HOP",
                                            "TIMEZONE_INCONSISTENT", "MESSAGE_ID_DOMAIN_MISMATCH"])

    # 13 truncated multipart message (an interrupted export).
    att = base64.encodebytes(b"%PDF-1.4\n" + b"% synthetic filler line\n" * 40 + b"%%EOF\n").decode()
    m = build(["Received: from smtp.example.org (smtp.example.org [192.0.2.25]) by mx.acme.example with ESMTPS id 7F; Thu, 12 Nov 2026 12:00:03 +0000",
               "From: Bruno Proveedor <bruno@example.org>", "To: Ana Compras <ana@acme.example>",
               "Subject: Documentación", "Date: Thu, 12 Nov 2026 13:00:00 +0100",
               "Message-ID: <20261112130000.14@example.org>", "MIME-Version: 1.0",
               "Content-Type: multipart/mixed; boundary=\"b13\""],
              "--b13\nContent-Type: text/plain; charset=utf-8\n\nAdjunto la documentación.\n--b13\n"
              "Content-Type: application/pdf; name=\"doc.pdf\"\nContent-Disposition: attachment; filename=\"doc.pdf\"\n"
              "Content-Transfer-Encoding: base64\n\n" + att + "--b13--\n")
    save("13-truncated.eml", m[: int(len(m) * 0.7)], ["FILE_STRUCTURE_DAMAGED", "DKIM_NOT_SIGNED"])

    # 14 valid signature of a sending service (not aligned with From), attachment dated after the message.
    att = base64.encodebytes(b"Fecha;Importe\n2026-11-12;100\n").decode()
    m = build(["Received: from out.mailer.example.com ([203.0.113.50]) by mx.acme.example with ESMTPS id 8A; Thu, 12 Nov 2026 14:00:05 +0000",
               "Received: from api.mailer.example.com by out.mailer.example.com with ESMTP id 8B; Thu, 12 Nov 2026 14:00:01 +0000",
               "From: Bruno Proveedor <bruno@example.org>", "To: Ana Compras <ana@acme.example>",
               "Subject: Informe semanal", "Date: Thu, 12 Nov 2026 15:00:00 +0100",
               "Message-ID: <20261112150000.15@example.org>", "MIME-Version: 1.0",
               "Content-Type: multipart/mixed; boundary=\"b14\""],
              "--b14\nContent-Type: text/plain; charset=utf-8\n\nInforme adjunto.\n--b14\n"
              "Content-Type: text/csv; name=\"informe.csv\"\n"
              "Content-Disposition: attachment; filename=\"informe.csv\"; modification-date=\"Fri, 13 Nov 2026 09:00:00 +0000\"\n"
              "Content-Transfer-Encoding: base64\n\n" + att + "--b14--\n")
    m = kmailer.sign(m, "m1", "mailer.example.com") + m
    save("14-not-aligned-attachment-date.eml", m,
         ["DKIM_SIGNATURE_VALID", "DKIM_DOMAIN_NOT_ALIGNED", "ATTACHMENT_DATE_AFTER_SENT"])

    # 15 forwarded: a selector whose key was not supplied, and an incomplete ARC set added by the forwarder.
    d15 = "Thu, 12 Nov 2026 16:00:00 +0100"
    m = core("Reenvío: horario", d15, "<20261112160000.16@example.org>", "Ana,\n\nel horario sigue igual.\n\nBruno\n")
    m = k2019.sign(m, "s2019", "example.org") + m
    m = prepend(["ARC-Seal: i=1; a=rsa-sha256; cv=none; d=forwarder.example.net; s=arc1; t=1794495600; b=dGVzdA==",
                 "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=forwarder.example.net; s=arc1; "
                 "t=1794495600; h=from:to:subject; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=dGVzdA=="], m)
    save("15-forwarded-unknown-key.eml", delivered(m, "Thu, 12 Nov 2026 15:00:06 +0000"),
         ["DKIM_KEY_NOT_AVAILABLE", "ARC_CHAIN_INVALID"])

    for name, data in files.items():
        (EV / name).write_bytes(data)
    # 16 truncated .msg (an interrupted copy of 11).
    full = (EV / "11-no-transport-headers.msg").read_bytes()
    (EV / "16-truncated.msg").write_bytes(full[:1536])
    expected["16-truncated.msg"] = ["FILE_STRUCTURE_DAMAGED"]

    keys = [
        "# rv-mailauth sample DKIM public keys (synthetic; the private keys were discarded after signing).",
        "# Simple form: selector._domainkey.domain<TAB>TXT value. BIND zone-file records are accepted too.",
        "s2026._domainkey.example.org\t" + k2026.txt,
        "# s2025 was rotated: this is the NEW key published under the same selector.",
        "s2025._domainkey.example.org\t" + k2025_new.txt,
        "ed2026._domainkey.example.org. 3600 IN TXT ( \"" + ked.txt[:30] + "\"",
        "        \"" + ked.txt[30:] + "\" ) ; Ed25519",
        "m1._domainkey.mailer.example.com. IN TXT \"" + kmailer.txt[:120] + "\" \"" + kmailer.txt[120:] + "\"",
        "# s2019._domainkey.example.org is deliberately missing (DKIM_KEY_NOT_AVAILABLE).",
    ]
    (SAMPLE / "dkim-keys.txt").write_text("\n".join(keys) + "\n", encoding="utf-8", newline="\n")
    del k2026, ked, k2025_old, k2025_new, kmailer, k2019  # discard every private key

    out = {
        "description": "Exact finding codes (sorted) per evidence file — and per mbox message as '<file>#<n>' — for a "
                       "run over examples/sample/evidence with the options below (paths relative to the repository "
                       "root). Written by tests/make_samples.py from the construction of each sample, not from a run.",
        "options": {"dkim_keys": "examples/sample/dkim-keys.txt", "own_domains": OWN},
        "args": ["--dkim-keys", "examples/sample/dkim-keys.txt", "--own-domain", OWN[0]],
        "files": dict(sorted(expected.items())),
    }
    out = with_status(out)
    (SAMPLE / "expected_findings.json").write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n",
                                                   encoding="utf-8", newline="\n")
    algos = ["md5", "sha1", "sha256", "sha512", "sha3-256", "blake3"]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["file", "size", *algos])
    for p in sorted(EV.iterdir()):
        b = p.read_bytes()
        digests = []
        for a in algos:
            if a == "blake3":
                digests.append(blake3.blake3(b).hexdigest())
            else:
                h = hashlib.new(a.replace("-", "_"))
                h.update(b)
                digests.append(h.hexdigest())
        w.writerow([p.name, len(b), *digests])
    (SAMPLE / "expected_hashes.csv").write_text(buf.getvalue(), encoding="utf-8", newline="\n")
    print(f"{len(list(EV.iterdir()))} samples, {len(expected)} expected entries, keys in {SAMPLE / 'dkim-keys.txt'}")


if __name__ == "__main__":
    if sys.argv[1:] == ["--refresh-status"]:
        # Re-derive status and exit_code of the committed expected_findings.json without new keys or samples.
        p = SAMPLE / "expected_findings.json"
        out = with_status(json.loads(p.read_text(encoding="utf-8")))
        p.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    else:
        main()
