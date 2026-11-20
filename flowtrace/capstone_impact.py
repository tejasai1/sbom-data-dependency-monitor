"""LLM impact report for one capstone repository, built only from MySQL facts."""
import json
import sys
from . import report_store

from .capstone_facts import build_facts
from .impact import RISK_LEVELS, VULN_ID, _load_json
from .providers import get_provider

SYSTEM_PROMPT = """You are the impact analyst for an SBoM vulnerability-monitoring platform.
You receive FACTS about one repository (the "system"): its known vulnerabilities from its
latest scan, the systems DOWNSTREAM of it (they receive its data, directly or through other
systems; "hops" is how many links away they are), the systems UPSTREAM of it (it receives
their data), each of those systems' own vulnerabilities, and the data flows between them.

Explain what could be affected if this system is compromised.

Rules:
- Use ONLY the facts given. Never invent systems, vulnerabilities, versions or data.
- Mention a vulnerability ID only if it appears in the facts.
- Downstream systems are potentially exposed, not confirmed compromised. Say "could be exposed".
- The data flows do not say what data moves. Do not guess the data; describe the systems.
- A system with 0 vulnerabilities can still be exposed through the data it receives.
- If "scanned" is false, the system has not been scanned yet. Say "not scanned yet",
  never "0 vulnerabilities" or "no findings".
- Give more weight to exposures that are closer (fewer hops) or that have their own
  high or critical findings.
- Recommendations must be concrete: name the package and the fixed version from the
  facts when one is listed.
- Write short, plain English for a security reviewer.

Respond with JSON only, in exactly this shape:
{"risk_level": "critical|high|medium|low",
 "summary": "2-3 sentences",
 "key_exposures": [{"system": "name exactly as in the facts", "reason": "one short sentence"}],
 "recommendations": ["up to 3 concrete actions"]}"""


def _systems(facts):
    """Every system named in the facts, in lower case."""
    names = {facts["system"]}
    for side in ("downstream", "upstream"):
        names |= {s["system"] for s in facts[side]}
    return {n.lower() for n in names}


def _vuln_ids(facts):
    """Every vulnerability ID that appears in the facts."""
    entries = [facts["vulnerabilities"]] + [
        s["vulnerabilities"] for side in ("downstream", "upstream") for s in facts[side]]
    return {v["id"].upper() for e in entries for v in e["most_serious"]}


def verify(report, facts):
    """Check the report only uses facts it was given. An empty list means it passed."""
    problems = []
    if report.get("risk_level") not in RISK_LEVELS:
        problems.append(f"unknown risk level: {report.get('risk_level')}")
    systems = _systems(facts)
    named = [k.get("system", "") if isinstance(k, dict) else str(k)
             for k in report.get("key_exposures", [])]
    unknown = [n for n in named if n.lower() not in systems]
    if unknown:
        problems.append(f"systems not in the facts: {unknown}")
    mentioned = {m.upper() for m in VULN_ID.findall(json.dumps(report))}
    invented = sorted(mentioned - _vuln_ids(facts))
    if invented:
        problems.append(f"vulnerability IDs not in the scans: {invented}")
    if len(report.get("recommendations", [])) > 3:
        problems.append("more than 3 recommendations")
    return problems


def assess(name, provider=None, force=False):
    """Build the facts, reuse a saved report if they are unchanged, otherwise ask the LLM.
    force=True always asks the LLM for a new report."""
    facts = build_facts(name)
    target_pk = facts.pop("target_pk")  # used for saving only, never sent to the model
    provider = provider or get_provider()
    fhash = report_store.facts_hash(facts)

    if not force:
        saved = report_store.find(target_pk, fhash, provider.model)
        if saved:
            return {"system": facts["system"], "model": provider.model,
                    "report": saved["report"], "problems": saved["problems"],
                    "facts": facts, "cached": True, "created_at": str(saved["created_at"])}

    reply = provider.complete(
        [{"role": "system", "content": SYSTEM_PROMPT},
         {"role": "user", "content": json.dumps(facts, indent=2, default=str)}],
        response_format={"type": "json_object"})
    report = _load_json(reply.content)
    problems = verify(report, facts)
    report_store.save(target_pk, fhash, provider.model, report, problems)
    return {"system": facts["system"], "model": provider.model,
            "report": report, "problems": problems, "facts": facts,
            "cached": False, "created_at": None}


if __name__ == "__main__":
    result = assess(sys.argv[1], force="--new" in sys.argv)
    source = (f"saved report from {result['created_at']}" if result["cached"]
              else "new report")
    print(f"Model: {result['model']} ({source})\n")
    print(json.dumps(result["report"], indent=2))
    print("\nVerification:", "passed" if not result["problems"] else result["problems"])