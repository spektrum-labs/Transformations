"""
Transformation: isPatchManagementValid
Vendor: ManageEngine Endpoint Central  |  Category: EPP
Evaluates: Whether patch management health policies are met and SLAs for remediation are satisfied.
Source: GET /api/1.4/patch/summary + GET /api/1.4/patch/healthpolicy
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPatchManagementValid", "vendor": "ManageEngine", "category": "EPP"}
        }
    }


def evaluate(data):
    """Validate patch management health and SLA compliance."""
    try:
        # Patch summary data
        total_patches = int(data.get("total_patches", data.get("totalPatches", data.get("total", 0))))
        installed = int(data.get("installed_patches", data.get("installedPatches", data.get("installed", 0))))
        missing = int(data.get("missing_patches", data.get("missingPatches", data.get("missing", 0))))
        healthy_systems = int(data.get("healthy_systems", data.get("healthySystems", data.get("healthy", 0))))
        vulnerable_systems = int(data.get("vulnerable_systems", data.get("vulnerableSystems", data.get("vulnerable", 0))))
        total_systems = int(data.get("total_systems", data.get("totalSystems", data.get("systems_scanned", 0))))

        # Check nested summary
        patch_summary = data.get("patch_summary", data.get("patchSummary", {}))
        if isinstance(patch_summary, dict) and not total_patches:
            total_patches = int(patch_summary.get("total", 0))
            installed = int(patch_summary.get("installed", 0))
            missing = int(patch_summary.get("missing", 0))

        # Health policy data (may be merged into same response)
        health_policy = data.get("health_policy", data.get("healthPolicy", {}))
        if isinstance(health_policy, dict):
            health_status = health_policy.get("status", health_policy.get("health_status", ""))
        else:
            health_status = data.get("health_status", data.get("healthStatus", ""))

        issues = []

        # Calculate patch compliance rate
        patch_compliance = 0.0
        if total_patches > 0:
            patch_compliance = (installed / total_patches) * 100

        # Calculate system health rate
        system_health = 0.0
        if total_systems > 0:
            system_health = (healthy_systems / total_systems) * 100
        elif (healthy_systems + vulnerable_systems) > 0:
            total_systems = healthy_systems + vulnerable_systems
            system_health = (healthy_systems / total_systems) * 100

        # Validation criteria
        is_valid = True

        if total_patches == 0 and total_systems == 0:
            is_valid = False
            issues.append("No patch data available")

        if missing > 0 and patch_compliance < 80:
            is_valid = False
            issues.append(f"Patch compliance is {round(patch_compliance, 1)}% - below 80% threshold")

        if vulnerable_systems > 0 and system_health < 80:
            is_valid = False
            issues.append(f"System health is {round(system_health, 1)}% - {vulnerable_systems} vulnerable systems detected")

        if isinstance(health_status, str) and health_status.lower() in ("unhealthy", "critical", "red", "failed"):
            is_valid = False
            issues.append(f"Health policy status: {health_status}")

        return {
            "isPatchManagementValid": is_valid,
            "patchCompliance": round(patch_compliance, 2),
            "systemHealth": round(system_health, 2),
            "totalPatches": total_patches,
            "installedPatches": installed,
            "missingPatches": missing,
            "healthySystems": healthy_systems,
            "vulnerableSystems": vulnerable_systems,
            "issues": issues
        }
    except Exception as e:
        return {"isPatchManagementValid": False, "error": str(e)}


def transform(input):
    criteriaKey = "isPatchManagementValid"
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error" and k != "issues"}
        issues = eval_result.get("issues", [])

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"Patch compliance: {extra_fields.get('patchCompliance', 0)}%")
            if extra_fields.get("systemHealth"):
                pass_reasons.append(f"System health: {extra_fields['systemHealth']}%")
            pass_reasons.append(f"Installed: {extra_fields.get('installedPatches', 0)}, Missing: {extra_fields.get('missingPatches', 0)}")
        else:
            for issue in issues:
                fail_reasons.append(issue)
            if not issues:
                fail_reasons.append("Patch management validation failed")
            if extra_fields.get("missingPatches", 0) > 0:
                recommendations.append(f"Deploy {extra_fields['missingPatches']} missing patches via Patch Management > Install Patch")
            if extra_fields.get("vulnerableSystems", 0) > 0:
                recommendations.append(f"Remediate {extra_fields['vulnerableSystems']} vulnerable systems")
            recommendations.append("Review patch health policy thresholds and enable auto-approval for critical patches")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "patchCompliance": extra_fields.get("patchCompliance", 0), "systemHealth": extra_fields.get("systemHealth", 0)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
