"""
Transformation: isStrongAuthRequired
Vendor: Generic IDP
Category: Identity / Authentication

Evaluates whether strong authentication is REQUIRED, by counting active authentication policies.

WHAT THIS FILE IS HANDED, AND THE BUG THAT FIXES
------------------------------------------------
Both Okta definitions wire this key to `getEstateSecondFactors`
(GET /api/v1/org/factors), which is NOT a policy list -- it is the Classic Engine
catalogue of which factor TYPES the org has available. Measured on a real tenant
2026-10-05 06:32 UTC: 17 rows, of which exactly two were ACTIVE -- `sms/OKTA` and
`token:software:totp/OKTA`.

The old logic counted "any item with status ACTIVE" and reported
    "Strong authentication is required with 2 active policies"
It was counting FACTORS and calling them POLICIES, so the pass was produced by SMS
and TOTP being switched on -- the two weakest factors in the list. Across the Okta
estate the key only ever read Passed, which is the distribution of a check that
cannot fail rather than a measurement of anyone's posture.

Two further problems with that reading, independent of the shape confusion:
  * an ACTIVE policy does not mean a policy that REQUIRES strong authentication;
  * an unreadable body returned False, so a failed read scored as a finding.

WHAT IT DOES NOW
----------------
Shape-aware, because this file is shared and a vendor that really does send a policy
list must keep working:

  * items carrying `factorType` -> an org FACTOR catalogue. It cannot evidence what any
    policy requires, so the answer is None (Unevaluated) with a reason naming the
    endpoint. Never True, never False.
  * a list of policy-shaped objects -> unchanged behaviour: True when at least one is
    ACTIVE, False when none is.
  * an error envelope, a non-list body, or an empty list -> None (Unevaluated).
    A read we could not perform is not a finding against the customer.

NOT PROVEN by a pass here: which users or applications the policy governs, and whether
the factors it permits are phishing-resistant. For Okta the phishing-resistance claims
live in isPhishingResistantOnlyEnabled and isAdminMFAPhishingResistant; what the org has
switched on lives in authTypesAllowed (which reads /api/v1/authenticators, the Identity
Engine surface, not this one).
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
                # Handle list in response wrapper
                if key in data and isinstance(data.get(key), list):
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
                "transformationId": "isStrongAuthRequired",
                "vendor": "Generic",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "isStrongAuthRequired"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                fail_reasons=["Input validation failed, so whether strong authentication "
                              "is required was not evaluated."]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # An error envelope is a read we could not perform, not a customer finding.
        if isinstance(data, dict):
            for marker in ["errorCode", "errorSummary", "errorMessage", "error", "errors"]:
                if data.get(marker):
                    return create_response(
                        result={criteriaKey: None},
                        validation=validation,
                        fail_reasons=["The identity provider returned an error instead of a "
                                      "policy list, so whether strong authentication is "
                                      "required was not evaluated."],
                        input_summary={"shape": "error"},
                    )

        if not isinstance(data, list):
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                fail_reasons=["No policy list in the response, so whether strong "
                              "authentication is required was not evaluated."],
                input_summary={"shape": "not-a-list"},
            )

        entries = [item for item in data if isinstance(item, dict)]
        if not entries:
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                fail_reasons=["The response carried no policy objects, so whether strong "
                              "authentication is required was not evaluated."],
                input_summary={"shape": "empty", "entries": len(data)},
            )

        # An Okta org FACTOR catalogue (GET /api/v1/org/factors) is not a policy list. It
        # says which factor types the org has available, never what any policy demands --
        # so counting its ACTIVE rows would report SMS being switched on as strong
        # authentication being required. Refuse to answer from it.
        factors = [item for item in entries if item.get("factorType")]
        if factors:
            active_factors = [
                str(item.get("factorType")) + "/" + str(item.get("provider") or "")
                for item in factors
                if str(item.get("status") or "").upper() == "ACTIVE"
            ]
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                fail_reasons=[
                    "Read a factor catalogue (GET /api/v1/org/factors), not an "
                    "authentication policy list: " + str(len(factors)) + " of "
                    + str(len(entries)) + " entries carry factorType. That endpoint lists "
                    "which factor types the org has available, not whether any policy "
                    "requires strong authentication, so this was not evaluated."
                ],
                recommendations=[
                    "Point this criterion at the authentication policies "
                    "(for Okta, GET /api/v1/policies?type=ACCESS_POLICY and its rules) "
                    "rather than at the org factor catalogue."
                ],
                input_summary={
                    "shape": "factor-catalogue",
                    "entries": len(entries),
                    "factorEntries": len(factors),
                    "activeFactors": sorted(active_factors),
                },
            )

        # A genuine policy list. Unchanged behaviour: active means in force.
        active_count = 0
        for item in entries:
            if str(item.get("status") or "").lower() == "active":
                active_count = active_count + 1
        is_required = active_count > 0

        if is_required:
            pass_reasons.append(f"Strong authentication is required with {active_count} active policies")
        else:
            fail_reasons.append("No strong authentication policies configured")
            recommendations.append("Enable strong authentication requirements")

        return create_response(
            result={criteriaKey: is_required},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"shape": "policies", "policies": len(entries),
                           "activePolicies": active_count}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error, so this was not evaluated: {str(e)}"]
        )
