"""
Transformation: isLifeCycleManagementEnabled
Vendor: Authomize
Category: Identity & Access Management

Evaluates isLifeCycleManagementEnabled for Authomize (IAM)
"""

import json
from datetime import datetime


def extract_input(input_data):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isLifeCycleManagementEnabled", "vendor": "Authomize", "category": "Identity & Access Management"}
        }
    }


def transform(input):
    criteriaKey = "isLifeCycleManagementEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        identities = data.get("identities", data.get("data", data.get("items", [])))

        if isinstance(identities, list) and len(identities) > 0:
            has_status_tracking = False
            has_orphan_detection = False

            for identity in identities:
                # Check for lifecycle status tracking
                status = identity.get("status", identity.get("state", ""))
                if status and str(status).lower() in ("active", "inactive", "disabled", "orphan", "stale"):
                    has_status_tracking = True
                # Check for orphan or stale account detection
                is_orphan = identity.get("isOrphan", identity.get("orphan", False))
                is_stale = identity.get("isStale", identity.get("stale", False))
                last_activity = identity.get("lastActivity", identity.get("lastSeen", None))

                if is_orphan or is_stale:
                    has_orphan_detection = True
                if last_activity is not None:
                    has_status_tracking = True

            result = has_status_tracking or has_orphan_detection
        # ── END EVALUATION LOGIC ──

        return create_response(

            result={"isLifeCycleManagementEnabled": result},

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
