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

        # A body that decodes to nothing carries no evidence either way.
        if data in (None, {}, [], ""):
            return create_response(
                result={criteriaKey: False},
                validation={"status": "error", "errors": ["the vendor returned no data to evaluate"], "warnings": []},
                api_errors=["the vendor returned no data to evaluate"],
            )

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
        # `password_policy_enforced = data is not None`, which has no reachable false past
        # the guard above: an error envelope, or a response to some other call, reported the
        # password policy enforced. The criterion was "did a response arrive".
        #
        # The shape read is Okta GET /api/v1/policies?type=PASSWORD -- the one production
        # definition measured pointing at this file is Okta's -- which answers with a JSON
        # ARRAY of Policy objects, each carrying id, type ("PASSWORD"), name and status
        # ("ACTIVE"/"INACTIVE") (https://developer.okta.com/docs/reference/api/policy/).
        # An Okta error is an object ({"errorCode": ..., "errorSummary": ...}), not an array.
        #
        # So admit only a policy collection, bare or under `policies`/`data`/`items`, and ask
        # the policy question of it: ENFORCED means at least one PASSWORD policy is ACTIVE.
        # The reachable false is a collection in which no policy is active (including a
        # named, explicitly empty one). Anything with no collection at all routes to
        # dataCollection.status="error": never listing the policies is not the same as
        # listing them and finding none enforced.
        policies = data if isinstance(data, list) else None
        if policies is None and isinstance(data, dict):
            for key in ("policies", "data", "items"):
                if isinstance(data.get(key), list):
                    policies = data[key]
                    break
        if policies is None:
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                api_errors=[("no policy collection in the /api/v1/policies?type=PASSWORD "
                             "response: the password policies were never listed, so their "
                             "enforcement cannot be reported either way")])

        active_policies = []
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            policy_type = policy.get("type")
            if isinstance(policy_type, str) and policy_type.upper() != "PASSWORD":
                continue
            status = policy.get("status")
            if isinstance(status, str) and status.upper() == "ACTIVE":
                active_policies.append(policy.get("name") or policy.get("id") or "unnamed")

        password_policy_enforced = len(active_policies) > 0

        if password_policy_enforced:
            pass_reasons.append(
                "Password policy is configured and ACTIVE: "
                + ", ".join([str(name) for name in active_policies[:5]]))
        else:
            fail_reasons.append(
                "The IDP returned " + str(len(policies)) + " password policy record(s) and "
                "none of them is ACTIVE, so no password policy is enforced")
            recommendations.append("Configure and enforce password policy in the IDP")

        return create_response(
            result={criteriaKey: password_policy_enforced},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"hasPasswordPolicy": password_policy_enforced,
                           "activePasswordPolicies": len(active_policies),
                           "passwordPolicyRecords": len(policies)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
