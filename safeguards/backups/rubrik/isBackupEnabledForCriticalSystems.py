"""
Transformation: isBackupEnabledForCriticalSystems
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether backup is enabled for critical systems by verifying that at least one active
SLA domain exists with a configured snapshot schedule AND that snappable objects have an effective
SLA domain assigned with backup compliance coverage.
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
                "transformationId": "isBackupEnabledForCriticalSystems",
                "vendor": "Rubrik",
                "category": "Backup"
            }
        }
    }


def has_active_schedule(snapshot_schedule):
    """Return True if any schedule tier has a frequency > 0."""
    if not snapshot_schedule or not isinstance(snapshot_schedule, dict):
        return False
    tiers = ["minute", "hourly", "daily", "weekly", "monthly", "quarterly", "yearly"]
    for tier in tiers:
        tier_data = snapshot_schedule.get(tier)
        if tier_data and isinstance(tier_data, dict):
            basic = tier_data.get("basicSchedule")
            if basic and isinstance(basic, dict):
                freq = basic.get("frequency", 0)
                if freq and freq > 0:
                    return True
    return False


def evaluate(data):
    """Core evaluation logic for isBackupEnabledForCriticalSystems."""
    try:
        sla_domains = data.get("slaDomains", [])
        snappables = data.get("snappables", [])

        if not isinstance(sla_domains, list):
            sla_domains = []
        if not isinstance(snappables, list):
            snappables = []

        # --- SLA Domain analysis ---
        active_sla_count = 0
        active_sla_names = []
        for domain in sla_domains:
            if not isinstance(domain, dict):
                continue
            schedule = domain.get("snapshotSchedule")
            if has_active_schedule(schedule):
                active_sla_count = active_sla_count + 1
                name = domain.get("name", "Unknown")
                active_sla_names.append(name)

        sla_enabled = active_sla_count > 0

        # --- Snappable (protected objects) analysis ---
        total_snappables = len(snappables)
        protected_count = 0
        compliant_count = 0
        unprotected_names = []

        for obj in snappables:
            if not isinstance(obj, dict):
                continue
            effective_sla = obj.get("effectiveSlaDomain")
            has_sla = (
                effective_sla is not None
                and isinstance(effective_sla, dict)
                and effective_sla.get("id") not in [None, "", "UNPROTECTED", "DO_NOT_PROTECT"]
            )
            if has_sla:
                protected_count = protected_count + 1
            else:
                obj_name = obj.get("name", "Unknown")
                unprotected_names.append(obj_name)

            compliance = obj.get("complianceStatus", "")
            if compliance == "IN_COMPLIANCE":
                compliant_count = compliant_count + 1

        # Compute protection ratio
        if total_snappables > 0:
            protection_ratio = (protected_count * 100) / total_snappables
            compliance_ratio = (compliant_count * 100) / total_snappables
        else:
            protection_ratio = 0.0
            compliance_ratio = 0.0

        # Pass if: at least one active SLA domain AND at least one protected snappable
        # When no snappables are reported, rely solely on SLA domain presence
        if total_snappables == 0:
            is_enabled = sla_enabled
        else:
            is_enabled = sla_enabled and protected_count > 0

        return {
            "isBackupEnabledForCriticalSystems": is_enabled,
            "activeSlaDomainsCount": active_sla_count,
            "activeSlaNames": active_sla_names,
            "totalSnappables": total_snappables,
            "protectedSnappablesCount": protected_count,
            "compliantSnappablesCount": compliant_count,
            "protectionCoveragePercentage": round(protection_ratio, 2),
            "compliancePercentage": round(compliance_ratio, 2),
            "unprotectedObjects": unprotected_names[:10]
        }
    except Exception as e:
        return {"isBackupEnabledForCriticalSystems": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupEnabledForCriticalSystems"
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

        active_sla = eval_result.get("activeSlaDomainsCount", 0)
        total_snappables = eval_result.get("totalSnappables", 0)
        protected = eval_result.get("protectedSnappablesCount", 0)
        compliant = eval_result.get("compliantSnappablesCount", 0)
        protection_pct = eval_result.get("protectionCoveragePercentage", 0.0)
        compliance_pct = eval_result.get("compliancePercentage", 0.0)
        active_names = eval_result.get("activeSlaNames", [])
        unprotected = eval_result.get("unprotectedObjects", [])

        if result_value:
            pass_reasons.append(
                str(active_sla) + " active SLA domain(s) found with configured snapshot schedules"
            )
            if total_snappables > 0:
                pass_reasons.append(
                    str(protected) + " of " + str(total_snappables) +
                    " snappable objects are protected by an SLA domain (" +
                    str(protection_pct) + "%)"
                )
            if active_names:
                pass_reasons.append("Active SLA domains: " + ", ".join(active_names))
        else:
            if active_sla == 0:
                fail_reasons.append("No active SLA domains with a configured snapshot schedule were found")
                recommendations.append(
                    "Create at least one SLA domain in Rubrik Security Cloud with a valid "
                    "snapshot schedule (daily, hourly, etc.) to ensure backup is active"
                )
            if total_snappables > 0 and protected == 0:
                fail_reasons.append(
                    "No snappable objects are assigned an effective SLA domain — "
                    "critical systems are not covered by any backup policy"
                )
                recommendations.append(
                    "Assign an SLA domain to all critical systems (VMs, databases, filesets) "
                    "in Rubrik Security Cloud to enable backup protection"
                )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        if total_snappables > 0:
            additional_findings.append(
                "Compliance rate: " + str(compliant) + " of " + str(total_snappables) +
                " objects are IN_COMPLIANCE (" + str(compliance_pct) + "%)"
            )
        if unprotected:
            additional_findings.append(
                "Sample unprotected objects: " + ", ".join(unprotected)
            )

        input_summary = {
            "slaDomainCount": len(data.get("slaDomains", [])) if isinstance(data, dict) else 0,
            "snappableCount": total_snappables,
            "activeSlaDomainsCount": active_sla,
            "protectedSnappablesCount": protected
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
