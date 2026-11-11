"""Transformation: hasMultiSourceTelemetryIntegration - Critical Start MDR (ZTAP), GET {serverUrl}/api/1.5/incidents/ (getIncidents).

Every ZTAP incident names the product that raised it: alert_source is the vendor's slug ("ms_sent") and
alert_source_display its label ("Microsoft Sentinel"). Sources are counted on one key per incident, the slug when it
is present and the label otherwise, normalised to lower-case letters and digits, so "Microsoft Sentinel",
"microsoft_sentinel" and "MicrosoftSentinel" are one source, not two. Two or more distinct sources across the
incidents read prove the MDR ingests telemetry from more than one tool, even on a partial read. False only on a
complete read of at least one incident where every incident names the same single source. No incidents, an error
body, a read in which no incident names a source, or a partial read with one source is not measured (None). An
incident that names no source is counted (unsourcedIncidents) and, when the named incidents all share one source,
makes the key not measured rather than False, since the unnamed incidents could come from a second tool; two named
sources still prove True. A label-only
incident is keyed through the slug that label is seen with on any incident carrying both fields, so "Microsoft
Sentinel" alone still lands on "ms_sent" when another incident pairs them; only a label that never appears beside a
slug, and is spelt unlike it, keys on its own. On the live body every incident carries both fields.
"""
import json
from datetime import datetime

VENDOR = "Critical Start"
WRAPPERS = ["result", "response", "apiResponse", "api_response", "Output", "data", "_response_data"]


def extract_validation(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data["validation"]
    return {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, metadata=None, transformation_errors=None, api_errors=None,
                    additional_findings=None):
    """Standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def error_in(cur):
    """A short error string when a vendor/IS error body is in hand, else None."""
    if cur.get("errors") or cur.get("error") is True or isinstance(cur.get("error"), (str, dict)):
        detail = cur.get("errors") or cur.get("error") or cur.get("message") or "error"
        return json.dumps(detail)[:300]
    if cur.get("errMsg") or cur.get("errNo"):
        return json.dumps(cur.get("errMsg") or cur.get("errNo"))[:300]
    code = cur.get("status_code") or cur.get("statusCode")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + json.dumps(cur.get("message") or cur.get("detail") or "")[:200]
    return None


def find_key(obj, wanted):
    """(container_dict, error) for the first dict, through any wrapper, that carries key `wanted`."""
    cur = obj
    for depth in range(8):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None
        if not isinstance(cur, dict):
            return None, None
        if wanted in cur:
            return cur, None
        problem = error_in(cur)
        if problem is not None:
            return None, problem
        nxt = None
        for key in WRAPPERS:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def raw_body(input):
    # input.get("data") makes Token-Service pass the undrilled response in a {data, validation}
    # envelope, so the vendor's total and the paginator's truncation flag stay visible.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def truncated(input, box):
    """True when the Integration-Service paginator marked the merged read partial."""
    for cur in (box, raw_body(input), input):
        if isinstance(cur, dict) and cur.get("paginationTruncated") is True:
            return True
    return False


def to_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def read_objects(input, noun):
    """(objects, complete, problem) from a ZTAP list read: {"objects": [...], "total": N, ...}."""
    box, problem = find_key(raw_body(input), "objects")
    if problem is not None:
        return None, False, "Critical Start returned an error instead of " + noun + ": " + problem
    if box is None or not isinstance(box.get("objects"), list):
        return None, False, "No Critical Start " + noun + " list in the response; nothing to evaluate."
    items = [o for o in box["objects"] if isinstance(o, dict)]
    if len(items) != len(box["objects"]):
        return None, False, "The " + noun + " list holds entries that are not records, so it cannot be scored."
    total = to_int(box.get("total"))
    if total is None:
        return None, False, "The " + noun + " list carries no readable total, so a complete read cannot be shown."
    complete = (not truncated(input, box)) and len(items) >= total
    return items, complete, None


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "mdr"},
    )


def normalise(value):
    """Lower-case letters and digits only, so a slug and its display label compare equal."""
    return "".join(c for c in value.lower() if c.isalnum())


def source_texts(incident):
    """(slug, label) of the product that raised the incident, each a stripped string or None."""
    texts = []
    for field in ("alert_source", "alert_source_display"):
        value = incident.get(field)
        if isinstance(value, dict):
            value = value.get("name") or value.get("display")
        texts.append(value.strip() if isinstance(value, str) and value.strip() else None)
    return texts[0], texts[1]


def source_keys(incidents):
    """({key: label}, unsourced): one key per product, and how many incidents name no source at all. First pass learns
    which label belongs to which slug from the incidents that carry both; second pass keys each incident by its slug,
    else by the slug its label is known to pair with, else by the label itself. Keys are normalised (lower-case
    letters and digits)."""
    alias = {}
    for i in incidents:
        slug, display = source_texts(i)
        if slug and display and normalise(slug) and normalise(display):
            alias[normalise(display)] = normalise(slug)
    labels = {}
    unsourced = 0
    for i in incidents:
        slug, display = source_texts(i)
        keyed = normalise(slug) if slug else ""
        if not keyed and display:
            keyed = alias.get(normalise(display)) or normalise(display)
        if not keyed:
            unsourced += 1
        elif keyed not in labels:
            labels[keyed] = display or slug
    return labels, unsourced


def transform(input):
    key = "hasMultiSourceTelemetryIntegration"
    validation = extract_validation(input)
    try:
        incidents, complete, problem = read_objects(input, "incidents")
        if problem is not None:
            return not_measured(key, problem, validation)
        if not incidents:
            return not_measured(key, "Critical Start returned no incidents, so no telemetry source can be shown.", validation)
        labels, unsourced = source_keys(incidents)
        sources = sorted(labels)
        if not sources:
            return not_measured(key, "None of the " + str(len(incidents)) + " incidents names its alert source, so the telemetry sources cannot be counted.", validation)
        if len(sources) >= 2:
            text = (str(len(sources)) + " distinct telemetry sources raised the " + str(len(incidents)) + " Critical Start incidents read: "
                    + ", ".join(labels[s] for s in sources) + ".")
            ok = True
        elif complete and unsourced:
            return not_measured(key, str(unsourced) + " of the " + str(len(incidents)) + " incidents name no alert source, so a second telemetry source behind the one named ("
                                + labels[sources[0]] + ") cannot be ruled out.", validation)
        elif complete:
            text = ("All " + str(len(incidents)) + " Critical Start incidents come from a single telemetry source (" + labels[sources[0]]
                    + "); no second tool feeds the MDR.")
            ok = False
        else:
            return not_measured(key, "Only part of the incident list was read and it shows one source; a partial read cannot show that no second source exists.", validation)
        return create_response(
            result={key: ok, "incidentsRead": len(incidents), "telemetrySourceCount": len(sources)},
            validation=validation,
            pass_reasons=[text] if ok else [],
            fail_reasons=[] if ok else [text],
            recommendations=[] if ok else ["Connect a second telemetry source (endpoint, identity, email or SIEM) to Critical Start so the MDR correlates across tools."],
            input_summary={"incidentsRead": len(incidents), "telemetrySources": [labels[s] for s in sources], "telemetrySourceKeys": sources, "unsourcedIncidents": unsourced, "completeRead": complete},
            metadata={"transformationId": key, "vendor": VENDOR, "category": "mdr"},
        )
    except Exception as e:
        return not_measured(key, "Transformation error: " + str(e), validation)
