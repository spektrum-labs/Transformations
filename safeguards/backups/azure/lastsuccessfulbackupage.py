"""
Transformation: lastSuccessfulBackupAge
Vendor: Azure Recovery Services  |  Category: Backups
Evaluates: Hours since the most recent successful backup across all protected items
"""
import json
from datetime import datetime, timezone


def extract_input(input_data):
    """Extract data and validation from input, handling both new and legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break

    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"]
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    """Create a standardized transformation response."""
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
                "transformationId": "lastSuccessfulBackupAge",
                "vendor": "Azure Recovery Services",
                "category": "Backups"
            }
        }
    }


def extract_protected_items(data):
    """Extract protected items from various input shapes.

    Handles:
    - dict with 'protectedItems' key (full API response)
    - dict with 'value' key (single vault response)
    - list of vault dicts each containing 'value' (unwrapped 'data' from Token-Service)
    - list of protected item dicts with 'properties' (flat list)
    """
    items = []

    if isinstance(data, dict):
        if 'protectedItems' in data:
            for entry in data['protectedItems']:
                if isinstance(entry, dict) and "value" in entry:
                    items.extend(entry["value"])
                elif isinstance(entry, list):
                    items.extend(entry)
            return items
        if 'value' in data:
            return data['value'] if isinstance(data['value'], list) else []

    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                if "value" in entry:
                    items.extend(entry["value"] if isinstance(entry["value"], list) else [])
                elif "properties" in entry:
                    items.append(entry)

    return items


def evaluate(data):
    """Evaluate last backup time across all vaults' protected items."""
    try:
        items = extract_protected_items(data)

        if not items:
            return {"lastSuccessfulBackupAge": "999", "error": "No protected items"}

        def parse_last_backup_time(backup_time_str):
            # Handles timestamps with/without fractions/with/without Z or +00:00 at end
            if not backup_time_str:
                return datetime(2000, 1, 1, tzinfo=timezone.utc)
            val = backup_time_str.strip()
            # Ensure UTC aware
            if val.endswith('Z'):
                val = val[:-1] + '+00:00'
            try:
                # Remove excessive microseconds if present (Python only supports up to 6 digits)
                if '.' in val:
                    dt_part, rest = val.split('.', 1)
                    frac, tz_part = rest.split('+', 1) if '+' in rest else (rest, None)
                    frac = frac[:6]  # take at most 6 digits
                    val = f"{dt_part}.{frac}"
                    if tz_part:
                        val += '+' + tz_part
                return datetime.fromisoformat(val)
            except Exception:
                # fallback to parsing without fractions if above fails
                try:
                    if '.' in val:
                        val = val.split('.')[0] + val[val.find('+'):]
                    return datetime.fromisoformat(val)
                except Exception:
                    return datetime(2000, 1, 1, tzinfo=timezone.utc)

        most_recent = max(
            (
                parse_last_backup_time(
                    (item.get('properties') or {}).get('lastBackupTime', '2000-01-01T00:00:00Z')
                )
                for item in items
            ),
            default=datetime(2000, 1, 1, tzinfo=timezone.utc)
        )
        hours_ago = int((datetime.now(timezone.utc) - most_recent).total_seconds() / 3600)
        return {"lastSuccessfulBackupAge": str(hours_ago), "hoursSinceLastBackup": hours_ago}
    except Exception as e:
        return {"lastSuccessfulBackupAge": "999", "error": str(e)}


def transform(input):
    """Calculates hours since last successful backup."""
    criteriaKey = "lastSuccessfulBackupAge"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, "999")
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value != "999":
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review Azure Recovery Services configuration for {criteriaKey}")

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
            result={criteriaKey: "999"},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
