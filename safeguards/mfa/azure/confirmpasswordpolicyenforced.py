"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Generic IDP
Category: Identity / Password Policy

Evaluates if the password policy is enforced for the given IDP.
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
                "transformationId": "confirmPasswordPolicyEnforced",
                "vendor": "Generic",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "confirmPasswordPolicyEnforced"

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

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # FAIL CLOSED ON A BODY THAT IS NOT A POLICY LIST. This used to read
        # `password_policy_enforced = data is not None`: an error envelope, or a response to
        # some other call, reported the password policy enforced.
        #
        # Every Microsoft product that carries this criterion routes it to Graph
        # GET /beta/identity/conditionalAccess/policies, a collection
        # {"@odata.context": ..., "value": [{id, displayName, state}, ...]}, where `state` is
        # "enabled", "disabled" or "enabledForReportingButNotEnforced". A Graph error is
        # {"error": {"code": ..., "message": ...}} and carries no such collection.
        #
        # So admit only that collection (or the bare array), and count a policy as enforced
        # only when its state is "enabled" -- report-only is by its own name not enforced,
        # and a record with no state says nothing. Anything with no collection routes to
        # dataCollection.status="error": the policies were never read.
        policies = data if isinstance(data, list) else None
        if policies is None and isinstance(data, dict) and isinstance(data.get("value"), list):
            policies = data["value"]
        if policies is None:
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                api_errors=[("no policy collection in the conditionalAccess/policies "
                             "response: the policies were never read, so their enforcement "
                             "cannot be reported either way")])

        enforced_policies = []
        for policy in policies:
            if isinstance(policy, dict) and str(policy.get("state") or "").lower() == "enabled":
                enforced_policies.append(policy.get("displayName") or policy.get("id") or "unnamed")

        password_policy_enforced = len(enforced_policies) > 0

        if password_policy_enforced:
            pass_reasons.append(
                "Enforced policy present: " + ", ".join([str(n) for n in enforced_policies[:5]]))
        else:
            fail_reasons.append(
                "Graph returned " + str(len(policies)) + " policy record(s) and none is "
                "enabled, so no password policy is enforced")
            recommendations.append("Configure and enforce password policy in the IDP")

        return create_response(
            result={criteriaKey: password_policy_enforced},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"hasPasswordPolicy": password_policy_enforced,
                           "enforcedPolicies": len(enforced_policies),
                           "policyRecords": len(policies)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
