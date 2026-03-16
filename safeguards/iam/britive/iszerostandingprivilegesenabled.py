"""
Transformation: isZeroStandingPrivilegesEnabled
Vendor: Britive  |  Category: Identity & Access Management
Evaluates: Whether profiles (PAPs) have expiration/session duration limits
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isZeroStandingPrivilegesEnabled", "vendor": "Britive", "category": "Identity & Access Management"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        # /api/apps/{appId}/paps returns profile objects:
        # { "papId": str, "name": str, "status": "active",
        #   "expirationInMinutes": int (0 = no expiry),
        #   "sessionDuration": int|null, ... }
        # Integration layer passes merged { "profiles": [...] }

        profiles = (
            data.get("profiles") or
            data.get("data") or
            data.get("paps") or
            (data if isinstance(data, list) else [])
        )

        if not isinstance(profiles, list):
            return {"isZeroStandingPrivilegesEnabled": False, "reason": "No profile data found"}

        # Only evaluate active profiles
        active_profiles = [
            p for p in profiles
            if p.get("status", "").lower() == "active"
        ]

        if len(active_profiles) == 0:
            # No active profiles — ZSP is vacuously true (nothing to check out)
            return {"isZeroStandingPrivilegesEnabled": True, "activeProfiles": 0, "reason": "No active profiles found"}

        total = len(active_profiles)
        profiles_without_expiry = []

        for profile in active_profiles:
            expiry = profile.get("expirationInMinutes", None)
            session = profile.get("sessionDuration", None)

            has_expiry = False

            if expiry is not None:
                try:
                    if int(expiry) > 0:
                        has_expiry = True
                except (TypeError, ValueError):
                    pass

            if not has_expiry and session is not None:
                try:
                    if int(session) > 0:
                        has_expiry = True
                except (TypeError, ValueError):
                    pass

            if not has_expiry:
                profiles_without_expiry.append(profile.get("name", profile.get("papId", "unknown")))

        result = len(profiles_without_expiry) == 0
    except Exception as e:
        return {"isZeroStandingPrivilegesEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isZeroStandingPrivilegesEnabled"
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

        # Run core evaluation
        eval_result = evaluate(data)

        # Extract the boolean result and any extra fields
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review Britive configuration for {criteriaKey}")

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
