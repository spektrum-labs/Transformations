"""
Transformation: isPatchManagementEnabled
Vendor: ManageEngine Endpoint Central  |  Category: EPP
Evaluates: Whether patch management scanning and deployment processes are configured.
Source: GET /api/1.4/patch/summary
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPatchManagementEnabled", "vendor": "ManageEngine", "category": "EPP"}
        }
    }


def evaluate(data):
    """Check if patch management is enabled from patch summary data."""
    try:
        # Patch summary returns counts of patches by status, systems scanned, etc.
        total_patches = int(data.get("total_patches", data.get("totalPatches", data.get("total", 0))))
        installed_patches = int(data.get("installed_patches", data.get("installedPatches", data.get("installed", 0))))
        missing_patches = int(data.get("missing_patches", data.get("missingPatches", data.get("missing", 0))))
        systems_scanned = int(data.get("systems_scanned", data.get("systemsScanned", data.get("scanned_systems", 0))))
        healthy_systems = int(data.get("healthy_systems", data.get("healthySystems", data.get("healthy", 0))))
        vulnerable_systems = int(data.get("vulnerable_systems", data.get("vulnerableSystems", data.get("vulnerable", 0))))

        # Check nested summary structures
        patch_summary = data.get("patch_summary", data.get("patchSummary", {}))
        if isinstance(patch_summary, dict) and not total_patches:
            total_patches = int(patch_summary.get("total", 0))
            installed_patches = int(patch_summary.get("installed", 0))
            missing_patches = int(patch_summary.get("missing", 0))

        # Patch management is considered enabled if:
        # 1. There are patches being tracked (total > 0)
        # 2. OR systems are being scanned
        # 3. OR there is any patch activity data
        is_enabled = (total_patches > 0) or (systems_scanned > 0) or (installed_patches > 0)

        # Check DB update status if available
        db_status = data.get("db_update_status", data.get("dbUpdateStatus", ""))
        last_scan = data.get("last_scan_time", data.get("lastScanTime", ""))

        return {
            "isPatchManagementEnabled": is_enabled,
            "totalPatches": total_patches,
            "installedPatches": installed_patches,
            "missingPatches": missing_patches,
            "systemsScanned": systems_scanned,
            "healthySystems": healthy_systems,
            "vulnerableSystems": vulnerable_systems
        }
    except Exception as e:
        return {"isPatchManagementEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isPatchManagementEnabled"
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

        if result_value:
            pass_reasons.append("Patch management is actively tracking patches")
            if extra_fields.get("totalPatches"):
                pass_reasons.append(f"Tracking {extra_fields['totalPatches']} patches across managed systems")
            if extra_fields.get("systemsScanned"):
                pass_reasons.append(f"{extra_fields['systemsScanned']} systems scanned")
            if extra_fields.get("missingPatches"):
                additional = f"{extra_fields['missingPatches']} missing patches detected"
                pass_reasons.append(additional)
        else:
            fail_reasons.append("No patch management activity detected in Endpoint Central")
            recommendations.append("Enable patch management in Endpoint Central and run an initial scan")
            recommendations.append("Configure automatic patch scanning schedule under Patch Management > Scan Systems")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
