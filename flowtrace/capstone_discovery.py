"""Phase 2: suggest data dependencies by letting FlowTrace read a system's code.

FlowTrace finds who CALLS whom. A data dependency in the capstone means who SENDS
DATA to whom, so each flow is turned into suggestions by where the data travels:
  - data RETURNED by the call  -> the called system sends data to the caller
  - data SENT with the call    -> the caller sends data to the called system
Suggestions are only proposals; a manager approves or rejects each one."""
import re
import sys
from dataclasses import asdict
from pathlib import Path

import pymysql

from .capstone_facts import DB_CONFIG, short_name
from .extractor import extract_flows
from .graph import normalize_name
from .providers import get_provider
from .reader import read_repository
from . import suggestion_store


def system_name(target_id):
    """Name used for prompts and matching: owner/repo for GitHub, the folder name for local targets."""
    t = target_id.rstrip("/\\")
    if "github.com" in t.lower():
        return short_name(t)
    return re.split(r"[\\/]", t)[-1] or t


def load_targets():
    """Returns {target_pk: target_id} and {target_pk: source_name (the group it was imported in)}."""
    conn = pymysql.connect(**DB_CONFIG)
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("SELECT target_pk, target_id, source_name FROM monitored_targets")
            rows = cur.fetchall()
    finally:
        conn.close()
    return ({r["target_pk"]: r["target_id"] for r in rows},
            {r["target_pk"]: r["source_name"] for r in rows})


def resolve(name, targets):
    """Find a target by its number, full target_id, owner/repo, or folder name."""
    wanted = name.strip().lower()
    for pk, tid in targets.items():
        if wanted in (str(pk), tid.lower(), short_name(tid).lower(), system_name(tid).lower()):
            return pk
    raise ValueError(f"Repository not found: {name}")


def name_index(targets, groups=None, group=None):
    """Matching key -> target_pk, only for targets in the same group (source_name),
    so a 'prometheus' in one company never matches another company's Prometheus.
    A key shared by two targets is dropped, so it never matches the wrong system."""
    index, shared = {}, set()
    for pk, tid in targets.items():
        if group is not None and (groups or {}).get(pk) != group:
            continue
        key = normalize_name(system_name(tid).split("/")[-1])
        if key in index:
            shared.add(key)
        else:
            index[key] = pk
    for key in shared:
        index.pop(key)
    return index


def to_suggestions(flows, index):
    """Turn FlowTrace's caller -> callee flows into 'sends data to' suggestions
    between registered targets. Systems that are not registered are listed separately."""
    suggestions, external = [], set()
    for f in flows:
        src = index.get(normalize_name(f.source))
        dst = index.get(normalize_name(f.destination))
        if src is None:
            external.add(f.source)
        if dst is None:
            external.add(f.destination)
        if src is None or dst is None or src == dst:
            continue
        base = {"data": f.data, "category": f.category, "mechanism": f.mechanism,
                "confidence": f.confidence, "evidence": [asdict(e) for e in f.evidence]}
        if f.returns:
            suggestions.append({**base, "source_pk": dst, "dest_pk": src, "items": f.returns,
                                "reason": "data returned by the call"})
        if f.fields or not f.returns:
            suggestions.append({**base, "source_pk": src, "dest_pk": dst, "items": f.fields,
                                "reason": "data sent with the call"})
    return suggestions, sorted(external)


def discover(name, provider=None, save=False):
    """Read one target's code, extract its data flows, and suggest data dependencies.
    save=True stores the suggestions for a manager to approve or reject."""
    targets, groups = load_targets()
    pk = resolve(name, targets)
    folder = Path(targets[pk])
    if not folder.is_dir():
        raise ValueError(f"{targets[pk]} is not a local folder. Only local folder targets "
                         "are supported for discovery so far.")
    label = system_name(targets[pk])
    files = read_repository(folder, repo_name=label)
    result = {"target_pk": pk, "system": label, "files": len(files),
              "flows": [], "rejected": [], "suggestions": [], "external": []}
    if not files:
        return result

    provider = provider or get_provider()
    accepted, rejected = extract_flows(provider, label, files)
    suggestions, external = to_suggestions(accepted, name_index(targets, groups, groups.get(pk)))
    names = {k: system_name(v) for k, v in targets.items()}
    for s in suggestions:
        s["source"], s["destination"] = names[s["source_pk"]], names[s["dest_pk"]]
    result.update(flows=[f.to_dict() for f in accepted],
                  rejected=[{"flow": raw, "problems": problems} for raw, problems in rejected],
                  suggestions=suggestions, external=external, model=provider.model)
    if save:
        added, skipped = suggestion_store.save(pk, provider.model, suggestions)
        result["saved"] = added
        result["skipped"] = [{"source": s["source"], "destination": s["destination"], "why": why}
                             for s, why in skipped]
    return result


if __name__ == "__main__":
    r = discover(sys.argv[1], save="--save" in sys.argv)
    print(f"{r['system']}: read {r['files']} files with {r.get('model', '-')}\n")
    print(f"Flows found in the code ({len(r['flows'])}):")
    for f in r["flows"]:
        where = ", ".join(f"{e['file']}:{e['start_line']}-{e['end_line']}" for e in f["evidence"])
        print(f"  {f['source']} -> {f['destination']}  [{f['category']}, {f['mechanism']}]  "
              f"{f['data']}  ({where})")
    if r["rejected"]:
        print(f"\nRejected by verification ({len(r['rejected'])}):")
        for item in r["rejected"]:
            print(f"  {item['flow'].get('source')} -> {item['flow'].get('destination')}: "
                  f"{item['problems']}")
    print(f"\nSuggested data dependencies ({len(r['suggestions'])}):")
    for s in r["suggestions"]:
        print(f"  {s['source']} sends data to {s['destination']}: {', '.join(s['items']) or s['data']}"
              f"  ({s['reason']})")
    print(f"\nSystems not registered as targets: {', '.join(r['external']) or 'none'}")
    if "saved" in r:
        print(f"\nSaved {r['saved']} new suggestion(s) for review.")
        for s in r["skipped"]:
            print(f"  skipped {s['source']} -> {s['destination']}: {s['why']}")
