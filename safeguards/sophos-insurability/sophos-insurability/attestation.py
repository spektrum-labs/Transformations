"""
Transformation: attestation
Vendor: Sophos Insurability  |  Category: sophos-insurability
Evaluates: Validates the full Sophos Insurability attestation by confirming
coverageAmount selection, Yes/No attestation fields, non-empty businessDescription,
and cross-referencing attestation claims against live Sophos Central API evidence
(account health checks and endpoint telemetry).
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
                "transformationId": "attestation",
                "vendor": "Sophos Insurability",
                "category": "sophos-insurability"
            }
        }
    }


def get_settings(data):
    """Extract user-provided attestation settings from data."""
    candidate = data.get("settings", {})
    if isinstance(candidate, dict) and candidate:
        return candidate
    # Settings may be merged directly at the top level alongside API keys
    return data


def endpoint_has_product(endpoint, code_substrings):
    """Return True if the endpoint has any assigned product whose code contains one of the given substrings."""
    assigned = endpoint.get("assignedProducts", [])
    for product in assigned:
        code = product.get("code", "").lower()
        for substring in code_substrings:
            if substring in code:
                return True
    return False


def evaluate(data):
    """Core evaluation logic for the attestation criteria key."""
    try:
        settings = get_settings(data)
        endpoints = data.get("endpoints", [])
        health_checks = data.get("healthChecks", {})
        if not isinstance(health_checks, dict):
            health_checks = {}
        overall_health = data.get("overallHealth", "unknown")

        # ------------------------------------------------------------------ #
        # 1. Validate coverageAmount selection                                #
        # ------------------------------------------------------------------ #
        coverage_amount = settings.get("coverageAmount", "")
        valid_coverages = ["$500K", "$1M", "$3M"]
        coverage_valid = coverage_amount in valid_coverages

        # ------------------------------------------------------------------ #
        # 2. Validate Yes/No attestation fields are properly answered         #
        # ------------------------------------------------------------------ #
        attestation_field_names = [
            "isMDRDeployed",
            "isMFAEnforced",
            "isBackupEnabled",
            "isEmailSecurityEnabled",
            "isEPPDeployed"
        ]
        attestation_values = {}
        invalid_attestation_fields = []
        for field in attestation_field_names:
            val = settings.get(field, "")
            attestation_values[field] = val
            if val not in ["Yes", "No"]:
                invalid_attestation_fields.append(field)
        attestations_valid = len(invalid_attestation_fields) == 0

        # ------------------------------------------------------------------ #
        # 3. Validate businessDescription is non-empty                        #
        # ------------------------------------------------------------------ #
        business_desc = settings.get("businessDescription", "")
        if not isinstance(business_desc, str):
            business_desc = str(business_desc)
        business_desc_valid = len(business_desc.strip()) > 0

        # ------------------------------------------------------------------ #
        # 4. Cross-reference attestation claims vs API evidence               #
        # ------------------------------------------------------------------ #
        discrepancies = []
        total_endpoints = len(endpoints)

        # --- isMDRDeployed ---
        mdr_claim = attestation_values.get("isMDRDeployed", "No")
        endpoints_with_mdr = 0
        for ep in endpoints:
            if endpoint_has_product(ep, ["mdr", "managed_detection"]):
                endpoints_with_mdr = endpoints_with_mdr + 1
        mdr_check = health_checks.get("mdrService", health_checks.get("mdr", {}))
        if not isinstance(mdr_check, dict):
            mdr_check = {}
        api_mdr_healthy = mdr_check.get("healthy", None)
        if mdr_claim == "Yes" and total_endpoints > 0:
            if endpoints_with_mdr == 0 and api_mdr_healthy is False:
                discrepancies.append(
                    "isMDRDeployed attested 'Yes' but MDR service not detected in endpoint telemetry or health check"
                )

        # --- isEPPDeployed ---
        epp_claim = attestation_values.get("isEPPDeployed", "No")
        epp_health = health_checks.get("endpointProtection", health_checks.get("threatProtection", {}))
        if not isinstance(epp_health, dict):
            epp_health = {}
        api_epp_healthy = epp_health.get("healthy", None)
        endpoints_without_epp = 0
        for ep in endpoints:
            if not endpoint_has_product(ep, ["endpointprotection", "interceptx", "intercept_x", "epp", "endpoint"]):
                endpoints_without_epp = endpoints_without_epp + 1
        if epp_claim == "Yes" and total_endpoints > 0:
            if api_epp_healthy is False:
                discrepancies.append(
                    "isEPPDeployed attested 'Yes' but endpoint protection health check is not healthy"
                )

        # Count endpoints with tamper protection disabled
        endpoints_without_tamper = 0
        for ep in endpoints:
            if ep.get("tamperProtectionEnabled", True) is False:
                endpoints_without_tamper = endpoints_without_tamper + 1

        # --- isMFAEnforced ---
        mfa_claim = attestation_values.get("isMFAEnforced", "No")
        mfa_check = health_checks.get("mfa", health_checks.get("identityProtection", {}))
        if not isinstance(mfa_check, dict):
            mfa_check = {}
        api_mfa_healthy = mfa_check.get("healthy", None)
        if mfa_claim == "Yes" and api_mfa_healthy is False:
            discrepancies.append(
                "isMFAEnforced attested 'Yes' but MFA health check indicates unhealthy status"
            )

        # --- isBackupEnabled ---
        backup_claim = attestation_values.get("isBackupEnabled", "No")
        backup_check = health_checks.get("backup", health_checks.get("dataBackup", {}))
        if not isinstance(backup_check, dict):
            backup_check = {}
        api_backup_healthy = backup_check.get("healthy", None)
        if backup_claim == "Yes" and api_backup_healthy is False:
            discrepancies.append(
                "isBackupEnabled attested 'Yes' but backup health check indicates unhealthy status"
            )

        # --- isEmailSecurityEnabled ---
        email_claim = attestation_values.get("isEmailSecurityEnabled", "No")
        email_check = health_checks.get("emailSecurity", health_checks.get("emailProtection", {}))
        if not isinstance(email_check, dict):
            email_check = {}
        api_email_healthy = email_check.get("healthy", None)
        if email_claim == "Yes" and api_email_healthy is False:
            discrepancies.append(
                "isEmailSecurityEnabled attested 'Yes' but email security health check indicates unhealthy status"
            )

        # ------------------------------------------------------------------ #
        # 5. Compute overall attestation result                               #
        # ------------------------------------------------------------------ #
        no_discrepancies = len(discrepancies) == 0
        attestation_result = coverage_valid and attestations_valid and business_desc_valid and no_discrepancies

        return {
            "attestation": attestation_result,
            "coverageAmount": coverage_amount,
            "coverageValid": coverage_valid,
            "attestationsValid": attestations_valid,
            "invalidAttestationFields": invalid_attestation_fields,
            "businessDescriptionProvided": business_desc_valid,
            "discrepancyCount": len(discrepancies),
            "discrepancies": discrepancies,
            "totalEndpoints": total_endpoints,
            "endpointsWithoutEPP": endpoints_without_epp,
            "endpointsWithoutTamperProtection": endpoints_without_tamper,
            "endpointsWithMDR": endpoints_with_mdr,
            "overallHealth": overall_health,
            "isMDRDeployed": mdr_claim,
            "isMFAEnforced": mfa_claim,
            "isBackupEnabled": backup_claim,
            "isEmailSecurityEnabled": email_claim,
            "isEPPDeployed": epp_claim
        }

    except Exception as e:
        return {"attestation": False, "error": str(e)}


def transform(input):
    criteriaKey = "attestation"
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

        # Coverage
        if eval_result.get("coverageValid", False):
            pass_reasons.append("Coverage amount '" + str(eval_result.get("coverageAmount", "")) + "' is a valid selection")
        else:
            fail_reasons.append(
                "Coverage amount '" + str(eval_result.get("coverageAmount", "")) +
                "' is not valid; must be one of $500K, $1M, or $3M"
            )
            recommendations.append("Select a valid coverage amount: $500K, $1M, or $3M")

        # Attestation fields
        if eval_result.get("attestationsValid", False):
            pass_reasons.append("All Yes/No attestation fields are properly answered")
        else:
            invalid_fields = eval_result.get("invalidAttestationFields", [])
            fail_reasons.append(
                "The following attestation fields have invalid or missing answers: " +
                ", ".join(invalid_fields)
            )
            recommendations.append(
                "Provide a valid 'Yes' or 'No' answer for all attestation fields: " +
                ", ".join(invalid_fields)
            )

        # Business description
        if eval_result.get("businessDescriptionProvided", False):
            pass_reasons.append("Business description has been provided")
        else:
            fail_reasons.append("Business description is empty or missing")
            recommendations.append(
                "Provide a non-empty description of your organization's primary business operations"
            )

        # Discrepancies
        discrepancies = eval_result.get("discrepancies", [])
        if len(discrepancies) == 0:
            pass_reasons.append(
                "No discrepancies detected between attestation claims and live Sophos Central API evidence"
            )
        else:
            for disc in discrepancies:
                fail_reasons.append("Discrepancy: " + disc)
            recommendations.append(
                "Review and resolve all discrepancies between your attestation answers and the Sophos Central API evidence"
            )

        # Endpoint telemetry findings
        total_eps = eval_result.get("totalEndpoints", 0)
        if total_eps > 0:
            eps_no_tamper = eval_result.get("endpointsWithoutTamperProtection", 0)
            if eps_no_tamper > 0:
                additional_findings.append(
                    str(eps_no_tamper) + " of " + str(total_eps) +
                    " endpoints have tamper protection disabled"
                )
            additional_findings.append(
                "Total managed endpoints evaluated: " + str(total_eps)
            )

        overall_health = eval_result.get("overallHealth", "unknown")
        if overall_health != "unknown":
            additional_findings.append("Sophos Central overall account health: " + str(overall_health))

        input_summary = {
            "coverageAmount": eval_result.get("coverageAmount", ""),
            "coverageValid": eval_result.get("coverageValid", False),
            "attestationsValid": eval_result.get("attestationsValid", False),
            "businessDescriptionProvided": eval_result.get("businessDescriptionProvided", False),
            "discrepancyCount": eval_result.get("discrepancyCount", 0),
            "totalEndpoints": total_eps,
            "overallHealth": overall_health
        }

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary=input_summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
