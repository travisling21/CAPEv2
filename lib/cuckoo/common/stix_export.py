# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2

"""Convert a CAPE analysis results dict into a STIX 2.1 bundle.

STIX 2.1 is just JSON with a well-defined schema, so we emit dicts
directly -- no need to add the `stix2` package as a new dependency.
The wire format is identical.

Spec reference: https://docs.oasis-open.org/cti/stix/v2.1/

Design notes:
- Every SDO's `id` is a deterministic UUIDv5 derived from the task id
  plus a per-SDO discriminator string.  Re-running the same task
  produces the same IDs, which lets downstream threat-intel platforms
  (MISP, OpenCTI, ThreatConnect) dedupe on first arrival.
- Mapping is defensive: missing keys in `results` produce a smaller
  bundle, never a traceback.  Malformed analyses shouldn't break
  reporting.
- We never emit external network calls; this is pure data
  transformation.
"""

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Stable namespace for UUIDv5.  Random once, frozen forever -- changing
# this would invalidate every downstream dedup key.
_CAPE_NAMESPACE = uuid.UUID("8e0c9e9f-7f6c-4f1a-9c10-1aa54a4d4d11")

_STIX_VERSION = "2.1"
_SPEC_VERSION = "2.1"

# Sandbox identity SDO -- always the same uuid for the same operator
# tool name.  Distinct per deployment if the operator overrides
# `identity_name` in conf/reporting.conf [stix].
DEFAULT_IDENTITY_NAME = "CAPE Sandbox"

_HEX_HASH = re.compile(r"^[0-9a-fA-F]+$")


def _stix_id(stix_type: str, *parts: Any) -> str:
    """Deterministic STIX object id.

    Same (type, parts) tuple -> same uuid -> same id.  Stable across
    re-runs of the same task.
    """
    key = "|".join(str(p) for p in parts)
    return f"{stix_type}--{uuid.uuid5(_CAPE_NAMESPACE, f'{stix_type}|{key}')}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _to_iso(ts: Any) -> str:
    """Best-effort coercion of CAPE timestamp strings to STIX format."""
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(ts, str) and ts:
        # CAPE often uses "%Y-%m-%d %H:%M:%S" or already-ISO strings.
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                )
            except ValueError:
                continue
        return ts
    return _now_iso()


def _valid_hex(value: Optional[str], length: int) -> bool:
    return bool(value) and len(value) == length and bool(_HEX_HASH.fullmatch(value))


def _file_hashes(file_info: dict) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    if _valid_hex(file_info.get("sha256"), 64):
        hashes["SHA-256"] = file_info["sha256"].lower()
    if _valid_hex(file_info.get("sha1"), 40):
        hashes["SHA-1"] = file_info["sha1"].lower()
    if _valid_hex(file_info.get("md5"), 32):
        hashes["MD5"] = file_info["md5"].lower()
    return hashes


def _identity(task_id: int, name: str) -> Dict[str, Any]:
    return {
        "type": "identity",
        "spec_version": _SPEC_VERSION,
        "id": _stix_id("identity", "sandbox", name),
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": name,
        "identity_class": "system",
        "description": f"CAPE Sandbox analysis task {task_id}",
    }


def _file_sco(file_info: dict) -> Optional[Dict[str, Any]]:
    """Build a File SCO from a CAPE file info dict.

    Shared across tasks: SHA-256 is the key so downstream threat-intel
    platforms dedupe the same binary across multiple analyses.
    """
    if not file_info:
        return None
    hashes = _file_hashes(file_info)
    if not hashes:
        # STIX File SCO doesn't strictly require hashes but the rest of
        # the bundle is useless without them.
        return None
    key = hashes.get("SHA-256") or hashes.get("SHA-1") or hashes.get("MD5")
    obj: Dict[str, Any] = {
        "type": "file",
        "spec_version": _SPEC_VERSION,
        "id": _stix_id("file", key),
        "hashes": hashes,
    }
    if file_info.get("name"):
        obj["name"] = file_info["name"]
    if isinstance(file_info.get("size"), int):
        obj["size"] = file_info["size"]
    if file_info.get("type"):
        # No STIX field for file format; store under "x_cape_file_type".
        obj["x_cape_file_type"] = file_info["type"]
    return obj


def _domain_sco(name: str) -> Dict[str, Any]:
    return {
        "type": "domain-name",
        "spec_version": _SPEC_VERSION,
        "id": _stix_id("domain-name", name),
        "value": name,
    }


def _ipv4_sco(addr: str) -> Dict[str, Any]:
    return {
        "type": "ipv4-addr",
        "spec_version": _SPEC_VERSION,
        "id": _stix_id("ipv4-addr", addr),
        "value": addr,
    }


def _url_sco(url: str) -> Dict[str, Any]:
    return {
        "type": "url",
        "spec_version": _SPEC_VERSION,
        "id": _stix_id("url", url),
        "value": url,
    }


def _malware_sdo(family: str, identity_id: str) -> Dict[str, Any]:
    return {
        "type": "malware",
        "spec_version": _SPEC_VERSION,
        "id": _stix_id("malware", family),
        "created_by_ref": identity_id,
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": family,
        "is_family": True,
    }


def _attack_pattern_sdo(technique_id: str, name: str, identity_id: str) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "type": "attack-pattern",
        "spec_version": _SPEC_VERSION,
        "id": _stix_id("attack-pattern", technique_id),
        "created_by_ref": identity_id,
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": name or technique_id,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            }
        ],
    }
    return obj


def _relationship_sro(
    task_id: int,
    rtype: str,
    source_ref: str,
    target_ref: str,
    identity_id: str,
) -> Dict[str, Any]:
    return {
        "type": "relationship",
        "spec_version": _SPEC_VERSION,
        "id": _stix_id("relationship", task_id, rtype, source_ref, target_ref),
        "created_by_ref": identity_id,
        "created": _now_iso(),
        "modified": _now_iso(),
        "relationship_type": rtype,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }


def _observed_data_sdo(
    task_id: int,
    object_refs: List[str],
    identity_id: str,
    first_seen: str,
    last_seen: str,
) -> Dict[str, Any]:
    return {
        "type": "observed-data",
        "spec_version": _SPEC_VERSION,
        "id": _stix_id("observed-data", task_id),
        "created_by_ref": identity_id,
        "created": _now_iso(),
        "modified": _now_iso(),
        "first_observed": first_seen,
        "last_observed": last_seen,
        "number_observed": 1,
        "object_refs": object_refs,
    }


def _report_sdo(
    task_id: int,
    object_refs: List[str],
    identity_id: str,
    published: str,
    *,
    score: Optional[float],
    package: Optional[str],
    report_url: Optional[str],
) -> Dict[str, Any]:
    labels: List[str] = ["malware-analysis"]
    if score is not None:
        try:
            if float(score) >= 5.0:
                labels.append("malicious-activity")
        except (TypeError, ValueError):
            pass
    sdo: Dict[str, Any] = {
        "type": "report",
        "spec_version": _SPEC_VERSION,
        "id": _stix_id("report", task_id),
        "created_by_ref": identity_id,
        "created": published,
        "modified": _now_iso(),
        "name": f"CAPE analysis task {task_id}",
        "published": published,
        "labels": labels,
        "object_refs": object_refs,
    }
    if package:
        sdo["x_cape_package"] = package
    if score is not None:
        sdo["x_cape_score"] = score
    if report_url:
        sdo["external_references"] = [{"source_name": "cape", "url": report_url}]
    return sdo


def _network_section(results: dict) -> Tuple[List[str], List[str], List[str]]:
    """Return (domains, ipv4s, urls) drawn from results['network']."""
    network = results.get("network")
    if not isinstance(network, dict):
        return [], [], []
    domains: List[str] = []
    ipv4s: List[str] = []
    urls: List[str] = []

    for entry in network.get("dns") or []:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        if request:
            domains.append(request)
        for ans in entry.get("answers") or []:
            if not isinstance(ans, dict):
                continue
            ip = ans.get("data")
            if ip and _looks_like_ipv4(ip):
                ipv4s.append(ip)

    for entry in (network.get("hosts") or []):
        if isinstance(entry, str) and _looks_like_ipv4(entry):
            ipv4s.append(entry)
        elif isinstance(entry, dict) and entry.get("ip"):
            ipv4s.append(entry["ip"])

    for entry in network.get("http") or []:
        if not isinstance(entry, dict):
            continue
        url = entry.get("uri")
        if url:
            urls.append(url)

    # Dedupe but preserve order.
    return _dedupe(domains), _dedupe(ipv4s), _dedupe(urls)


def _looks_like_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _dedupe(values: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _safe_int_task_id(results: dict) -> int:
    info = results.get("info") or {}
    try:
        return int(info.get("id") or 0)
    except (TypeError, ValueError):
        return 0


def _ttps(results: dict) -> List[Tuple[str, str]]:
    """Yield (technique_id, name) pairs from results['ttps'].

    CAPE's TTP shape varies; handle both list-of-dict and dict.
    """
    out: List[Tuple[str, str]] = []
    ttps = results.get("ttps")
    if isinstance(ttps, list):
        for entry in ttps:
            if not isinstance(entry, dict):
                continue
            tid = entry.get("ttp") or entry.get("technique_id") or entry.get("id")
            name = entry.get("name") or entry.get("technique") or ""
            if tid:
                out.append((str(tid), str(name)))
    elif isinstance(ttps, dict):
        for tid, meta in ttps.items():
            name = ""
            if isinstance(meta, dict):
                name = meta.get("name") or ""
            out.append((str(tid), str(name)))
    return out


def _families(results: dict) -> List[str]:
    detections = results.get("detections") or []
    out = []
    for d in detections:
        if isinstance(d, dict):
            fam = d.get("family")
            if fam:
                out.append(str(fam))
        elif isinstance(d, str):
            out.append(d)
    return _dedupe(out)


def make_bundle(results: dict, *, identity_name: str = DEFAULT_IDENTITY_NAME) -> Dict[str, Any]:
    """Build a STIX 2.1 bundle from a CAPE results dict.

    Always returns a valid bundle, even for empty/malformed input
    (just with fewer objects).
    """
    task_id = _safe_int_task_id(results)
    info = results.get("info") or {}
    target = results.get("target") or {}
    file_info = target.get("file") or {}

    identity = _identity(task_id, identity_name)
    objects: List[Dict[str, Any]] = [identity]
    object_refs: List[str] = [identity["id"]]

    # Sample file SCO.  Shared across tasks (SHA-256 = same file).
    sample_obj = _file_sco(file_info)
    sample_id: Optional[str] = None
    if sample_obj:
        objects.append(sample_obj)
        object_refs.append(sample_obj["id"])
        sample_id = sample_obj["id"]

    # Detected malware family / families.
    family_relationships: List[Dict[str, Any]] = []
    for family in _families(results):
        mal = _malware_sdo(family, identity["id"])
        objects.append(mal)
        object_refs.append(mal["id"])
        if sample_id:
            rel = _relationship_sro(task_id, "indicates", sample_id, mal["id"], identity["id"])
            family_relationships.append(rel)

    # Network indicators.  SCOs shared across tasks; Relationships
    # task-scoped.
    domains, ipv4s, urls = _network_section(results)
    network_object_ids: List[str] = []
    for d in domains:
        sco = _domain_sco(d)
        objects.append(sco)
        network_object_ids.append(sco["id"])
    for ip in ipv4s:
        sco = _ipv4_sco(ip)
        objects.append(sco)
        network_object_ids.append(sco["id"])
    for u in urls:
        sco = _url_sco(u)
        objects.append(sco)
        network_object_ids.append(sco["id"])
    object_refs.extend(network_object_ids)

    # MITRE ATT&CK techniques as AttackPattern SDOs.
    technique_attack_ids: List[str] = []
    uses_relationships: List[Dict[str, Any]] = []
    for tid, tname in _ttps(results):
        ap = _attack_pattern_sdo(tid, tname, identity["id"])
        objects.append(ap)
        technique_attack_ids.append(ap["id"])
        if sample_id:
            rel = _relationship_sro(task_id, "uses", sample_id, ap["id"], identity["id"])
            uses_relationships.append(rel)
    object_refs.extend(technique_attack_ids)

    # ObservedData SDO grouping the SCOs (sample + network).
    observed_refs = [sid for sid in [sample_id] + network_object_ids if sid]
    started = _to_iso(info.get("started"))
    ended = _to_iso(info.get("ended"))
    if observed_refs:
        observed = _observed_data_sdo(task_id, observed_refs, identity["id"], started, ended)
        objects.append(observed)
        object_refs.append(observed["id"])

    # Relationships listed last so they appear after the SDOs they
    # reference (cosmetic only -- order isn't significant in STIX
    # bundles).  Their IDs also need to land in object_refs so the
    # wrapping Report SDO includes them.
    objects.extend(uses_relationships)
    object_refs.extend(r["id"] for r in uses_relationships)
    objects.extend(family_relationships)
    object_refs.extend(r["id"] for r in family_relationships)

    # Wrap everything in a Report SDO.
    report = _report_sdo(
        task_id,
        object_refs=object_refs[:],
        identity_id=identity["id"],
        published=ended,
        score=info.get("score"),
        package=info.get("package"),
        report_url=results.get("report_url"),
    )
    objects.append(report)

    return {
        "type": "bundle",
        "id": _stix_id("bundle", task_id),
        "spec_version": _STIX_VERSION,  # legacy field tolerated by 2.1 consumers
        "objects": objects,
    }
