"""
Transformation: isBackupEnabled
Vendor: Rubrik  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Verifies that at least one active SLA Domain backup policy exists with a configured
snapshot schedule (daily, weekly, or monthly), AND that the count of objects with
protectionStatus Protected is greater than zero — confirming backup protection is enabled
in Rubrik Security Cloud.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBackupEnabled",
                "vendor": "Rubrik",
                "category": "control-objectives-for-information-and-related-technologies-cobit"
            }
        }
    }


def find_sla_domains(data):
    """
    Attempt to extract SLA domain nodes from multiple possible data shapes.
    getSLADomains returnSpec: data = data.slaDomains.nodes (array of domain objects)
    When merged with getProtectedObjects (also uses key 'data'), the SLA domains
    list may be at the top-level 'data' key or nested under 'slaDomains'.
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        inner = data.get("data", None)
        if isinstance(inner, list):
            return inner
        sla = data.get("slaDomains", {})
        if isinstance(sla, dict):
            nodes = sla.get("nodes", [])
            if isinstance(nodes, list):
                return nodes
        if isinstance(inner, dict):
            sla2 = inner.get("slaDomains", {})
            if isinstance(sla2, dict):
                nodes2 = sla2.get("nodes", [])
                if isinstance(nodes2, list):
                    return nodes2
    return []


def find_protected_objects(data):
    """
    Attempt to extract snappableConnection from multiple possible data shapes.
    getProtectedObjects returnSpec: data = data.snappableConnection
    Returns (count, nodes) tuple.
    """
    if isinstance(data, dict):
        snap = data.get("snappableConnection", None)
        if isinstance(snap, dict):
            return snap.get("count", 0), snap.get("nodes", [])
        inner = data.get("data", {})
        if isinstance(inner, dict):
            snap2 = inner.get("snappableConnection", None)
            if isinstance(snap2, dict):
                return snap2.get("count", 0), snap2.get("nodes", [])
        if "count" in data and "nodes" in data:
            return data.get("count", 0), data.get("nodes", [])
    return 0, []


def has_active_schedule(domain):
    """Return True if a domain node has at least one configured snapshot schedule."""
    schedule = domain.get("snapshotSchedule", None)
    if not isinstance(schedule, dict):
        return False
    for period in ["daily", "weekly", "monthly", "yearly"]:
        period_config = schedule.get(period, None)
        if isinstance(period_config, dict):
            basic = period_config.get("basicSchedule", None)
            if isinstance(basic, dict) and basic.get("frequency", 0):
                return True
    return False


def evaluate(data):
    """Core evaluation logic for isBackupEnabled."""
    try:
        sla_domains = find_sla_domains(data)
        protected_count, protected_nodes = find_protected_objects(data)

        total_sla_domains = len(sla_domains)
        active_sla_domains = [d for d in sla_domains if has_active_schedule(d)]
        active_sla_count = len(active_sla_domains)
        active_sla_names = [d.get("name", "unnamed") for d in active_sla_domains]

        if protected_count == 0 and isinstance(protected_nodes, list) and len(protected_nodes) > 0:
            protected_count = len(protected_nodes)

        sla_enabled = active_sla_count > 0
        objects_protected = protected_count > 0

        is_backup_enabled = sla_enabled or objects_protected

        return {
            "isBackupEnabled": is_backup_enabled,
            "totalSlaDomains": total_sla_domains,
            "activeSlaDomains": active_sla_count,
            "activeSlaNames": active_sla_names,
            "protectedObjectCount": protected_count,
            "slaDomainCheckPassed": sla_enabled,
            "protectedObjectsCheckPassed": objects_protected
        }
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            if eval_result.get("slaDomainCheckPassed"):
                pass_reasons.append(
                    str(eval_result.get("activeSlaDomains", 0)) +
                    " active SLA Domain(s) with configured snapshot schedules found"
                )
                active_names = eval_result.get("activeSlaNames", [])
                if active_names:
                    additional_findings.append("Active SLA Domains: " + ", ".join(active_names))
            if eval_result.get("protectedObjectsCheckPassed"):
                pass_reasons.append(
                    str(eval_result.get("protectedObjectCount", 0)) +
                    " protected object(s) confirmed under active SLA Domains"
                )
        else:
            if not eval_result.get("slaDomainCheckPassed"):
                fail_reasons.append(
                    "No active SLA Domains with configured snapshot schedules found "
                    "(total SLA Domains: " + str(eval_result.get("totalSlaDomains", 0)) + ")"
                )
                recommendations.append(
                    "Create and activate at least one SLA Domain with a daily, weekly, or monthly snapshot schedule in Rubrik Security Cloud"
                )
            if not eval_result.get("protectedObjectsCheckPassed"):
                fail_reasons.append("No protected objects found under any SLA Domain")
                recommendations.append(
                    "Assign workloads to an active SLA Domain to ensure they are protected by backup policies"
                )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        input_summary = {
            "totalSlaDomains": eval_result.get("totalSlaDomains", 0),
            "activeSlaDomains": eval_result.get("activeSlaDomains", 0),
            "protectedObjectCount": eval_result.get("protectedObjectCount", 0)
        }

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
