"""
Transformation: isBackupEnabledForCriticalSystems
Vendor: Azure Recovery Services
Category: Backup / Data Protection

Checks that Azure backup protected items exist, indicating critical systems
are covered by backup policies.

Data source: Azure Recovery Services backupProtectedItems API returning
items with protectionStatus and sourceResourceId.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEnabledForCriticalSystems", "vendor": "Azure", "category": "Backup"}
        }
    }


def transform(input):
    """Evaluates whether Azure backup protects critical systems by checking protected items."""
    criteriaKey = "isBackupEnabledForCriticalSystems"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Merged protectedItems from iterating across all vaults, or direct { "value": [...] }
        items_data = data.get("protectedItems", data)
        all_items = []
        if isinstance(items_data, list):
            for entry in items_data:
                if isinstance(entry, dict) and "value" in entry:
                    all_items.extend(entry["value"])
                elif isinstance(entry, list):
                    all_items.extend(entry)
        elif isinstance(items_data, dict):
            all_items = items_data.get("value", [])

        protected_items = all_items
        active_items = []

        for item in protected_items:
            props = item.get("properties", {})
            status = (props.get("protectionStatus") or props.get("protectionState") or "").lower()
            # Azure uses 'Protected', 'ProtectionConfigured', 'Healthy' etc.
            if status in ("protected", "protectionconfigured", "healthy"):
                active_items.append({
                    "name": item.get("name", "Unknown"),
                    "sourceResourceId": props.get("sourceResourceId", ""),
                    "workloadType": props.get("workloadType", "")
                })

        found = len(active_items) > 0

        if found:
            pass_reasons.append(f"Backups enabled for {len(active_items)} protected items across critical systems")
        else:
            fail_reasons.append("No actively protected backup items found")
            recommendations.append("Enable Azure Backup protection for all critical VMs, databases, and storage accounts")

        return create_response(
            result={criteriaKey: found, "protectedItemsCount": len(active_items), "totalItems": len(protected_items)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"activeProtectedItems": len(active_items), "totalItems": len(protected_items)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
