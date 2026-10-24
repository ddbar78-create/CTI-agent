"""
Exporterar insamlade IOC:er i standardformat, så de kan matas in i MISP,
OpenCTI, brandväggar, proxyservrar eller SIEM — utan manuellt arbete.

Skrivs till mappen exports/ (committas av workflowet och blir nåbara via
GitHub Pages, t.ex. https://<användare>.github.io/<repo>/exports/blocklist-domains.txt):

  iocs.csv               alla IOC:er (typ, värde, familj, confidence, källa, datum)
  blocklist-domains.txt  domäner, en per rad  (poäng >= 70 och inte inaktuella, se ioc_confidence.py)
  blocklist-ips.txt      publika IPv4-adresser, en per rad  (samma kriterium)
  blocklist-urls.txt     URL:er, en per rad  (samma kriterium)
  blocklist-sha256.txt   SHA-256-hashar, en per rad  (samma kriterium)
  iocs-stix.json         STIX 2.1-bundle (indicator + malware + relationship)

Blocklistorna och STIX innehåller bara IOC:er från källor som anger
confidence (ThreatFox, URLhaus, Feodo, MalwareBazaar, OpenPhish ...). IOC:er
som bara regex-plockats ur artikeltext är för brusiga för att blockera på och
ingår därför enbart i iocs.csv.
"""

import csv
import ipaddress
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone

from storage import DB_PATH

try:
    from attack_mapping import parse_family_from_value
except Exception:  # pragma: no cover
    parse_family_from_value = None

EXPORT_DIR = "exports"
MIN_CONFIDENCE = 75
MAX_ROWS = 20000
MAX_STIX_INDICATORS = 3000

_NS = uuid.UUID("5d8a9f0e-3c1b-4d52-9a77-0a1b2c3d4e5f")
_CONF_RE = re.compile(r"confidence\s+(\d+)", re.I)
_FAMILY_RE = re.compile(r"\[([^\],]+),")
IDENTITY_ID = "identity--" + str(uuid.uuid5(_NS, "cti-agent"))
_FIXED_TS = "2026-01-01T00:00:00.000Z"


def _family(value: str) -> str:
    if parse_family_from_value:
        try:
            return parse_family_from_value(value) or ""
        except Exception:
            pass
    m = _FAMILY_RE.search(value)
    return m.group(1).strip() if m else ""


def _confidence(value: str):
    m = _CONF_RE.search(value)
    return int(m.group(1)) if m else None


def _ts(fetched_at: str) -> str:
    """SQLite 'YYYY-MM-DD HH:MM:SS' -> STIX 'YYYY-MM-DDTHH:MM:SS.000Z'."""
    try:
        dt = datetime.strptime((fetched_at or "")[:19], "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except ValueError:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _is_public_ipv4(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return ip.version == 4 and ip.is_global


def _esc_stix(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'")


def _pattern(ioc_type: str, clean: str):
    v = _esc_stix(clean)
    if ioc_type == "domain":
        return f"[domain-name:value = '{v}']"
    if ioc_type == "url":
        return f"[url:value = '{v}']"
    if ioc_type in ("ipv4", "ip:port"):
        ip = clean.split(":")[0]
        return f"[ipv4-addr:value = '{_esc_stix(ip)}']" if _is_public_ipv4(ip) else None
    if ioc_type == "sha256_hash":
        return f"[file:hashes.'SHA-256' = '{v}']"
    if ioc_type == "sha1_hash":
        return f"[file:hashes.'SHA-1' = '{v}']"
    if ioc_type == "md5_hash":
        return f"[file:hashes.MD5 = '{v}']"
    return None


def load_rows(db_path: str = DB_PATH) -> list:
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT iocs.ioc_type, iocs.value, articles.feed, articles.fetched_at
            FROM iocs JOIN articles ON articles.id = iocs.article_id
            ORDER BY iocs.id DESC LIMIT ?
            """,
            (MAX_ROWS,),
        ).fetchall()
    except sqlite3.Error:
        rows = []
    conn.close()

    try:
        from ioc_confidence import load_scores, MIN_BLOCK_SCORE
        scores = load_scores(db_path)
    except Exception:  # pragma: no cover
        scores, MIN_BLOCK_SCORE = {}, 70

    out, seen = [], set()
    for ioc_type, value, feed, fetched in rows:
        clean = str(value).split(" [")[0].strip()
        key = (ioc_type, clean.lower())
        if not clean or key in seen:
            continue
        seen.add(key)
        conf = _confidence(str(value))
        sc = scores.get((ioc_type, clean.lower()))
        if sc:  # poäng och status från ioc_confidence.py (åldrande, flera källor)
            ok = sc[0] >= MIN_BLOCK_SCORE and sc[1] != "inaktuell"
            conf = sc[0]
        else:   # utan poäng: gamla regeln (källans egen confidence)
            ok = conf is not None and conf >= MIN_CONFIDENCE
        out.append({
            "type": ioc_type, "value": clean, "family": _family(str(value)),
            "confidence": conf, "source": feed or "", "seen": (fetched or "")[:19],
            "ok": ok, "status": sc[1] if sc else "",
        })
    return out


def build_stix(rows: list) -> dict:
    objects = [{
        "type": "identity", "spec_version": "2.1", "id": IDENTITY_ID,
        "created": _FIXED_TS, "modified": _FIXED_TS, "name": "CTI-agent",
        "identity_class": "system",
        "description": "Automatiskt insamlade indikatorer (ThreatFox, URLhaus, Feodo m.fl.).",
    }]
    malware_ids = {}
    indicators = 0

    for r in rows:
        if not r.get("ok"):
            continue
        pattern = _pattern(r["type"], r["value"])
        if not pattern:
            continue
        if indicators >= MAX_STIX_INDICATORS:
            break
        ts = _ts(r["seen"])
        ind_id = "indicator--" + str(uuid.uuid5(_NS, f"{r['type']}|{r['value'].lower()}"))
        ind = {
            "type": "indicator", "spec_version": "2.1", "id": ind_id,
            "created": ts, "modified": ts, "created_by_ref": IDENTITY_ID,
            "name": f"{r['family'] or 'Malicious'} {r['type']}: {r['value'][:80]}",
            "pattern": pattern, "pattern_type": "stix", "valid_from": ts,
            "confidence": int(r["confidence"]),
            "labels": ["malicious-activity"],
        }
        if r["type"] == "ip:port":
            ind["description"] = f"Observerad som {r['value']} (IP:port)."
        objects.append(ind)
        indicators += 1

        if r["family"]:
            mid = malware_ids.get(r["family"].lower())
            if not mid:
                mid = "malware--" + str(uuid.uuid5(_NS, "malware|" + r["family"].lower()))
                malware_ids[r["family"].lower()] = mid
                objects.append({
                    "type": "malware", "spec_version": "2.1", "id": mid,
                    "created": _FIXED_TS, "modified": _FIXED_TS, "created_by_ref": IDENTITY_ID,
                    "name": r["family"], "is_family": True,
                })
            objects.append({
                "type": "relationship", "spec_version": "2.1",
                "id": "relationship--" + str(uuid.uuid5(_NS, f"rel|{ind_id}|{mid}")),
                "created": ts, "modified": ts, "created_by_ref": IDENTITY_ID,
                "relationship_type": "indicates", "source_ref": ind_id, "target_ref": mid,
            })

    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objects}


def export_all(db_path: str = DB_PATH, out_dir: str = EXPORT_DIR) -> dict:
    """Skriver alla exportfiler. Returnerar antal poster per fil."""
    os.makedirs(out_dir, exist_ok=True)
    rows = load_rows(db_path)
    good = [r for r in rows if r.get("ok")]

    with open(os.path.join(out_dir, "iocs.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type", "value", "family", "score", "status", "source", "first_seen_utc"])
        for r in rows:
            w.writerow([r["type"], r["value"], r["family"], r["confidence"] if r["confidence"] is not None else "",
                        r.get("status", ""), r["source"], r["seen"]])

    def _write_list(name, values):
        values = sorted(set(values))
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            f.write("\n".join(values) + ("\n" if values else ""))
        return len(values)

    counts = {"iocs.csv": len(rows)}
    counts["blocklist-domains.txt"] = _write_list(
        "blocklist-domains.txt", [r["value"].lower() for r in good if r["type"] == "domain"])
    counts["blocklist-ips.txt"] = _write_list(
        "blocklist-ips.txt",
        [r["value"].split(":")[0] for r in good
         if r["type"] in ("ipv4", "ip:port") and _is_public_ipv4(r["value"].split(":")[0])])
    counts["blocklist-urls.txt"] = _write_list("blocklist-urls.txt", [r["value"] for r in good if r["type"] == "url"])
    counts["blocklist-sha256.txt"] = _write_list(
        "blocklist-sha256.txt", [r["value"].lower() for r in good if r["type"] == "sha256_hash"])

    bundle = build_stix(rows)
    with open(os.path.join(out_dir, "iocs-stix.json"), "w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=1)
    counts["iocs-stix.json"] = sum(1 for o in bundle["objects"] if o["type"] == "indicator")

    print(f"    Export: " + ", ".join(f"{k} ({v})" for k, v in counts.items()))
    return counts


if __name__ == "__main__":
    export_all()
