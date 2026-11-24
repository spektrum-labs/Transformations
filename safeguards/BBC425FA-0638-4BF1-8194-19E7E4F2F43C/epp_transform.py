"""
Transformation: epp_transform
Vendor: Halcyon (Endpoint Security)
Category: Endpoint Security

NOT MEASURED. Every key below returns None with a dataCollection error, so it reads Unevaluated
-- never Passed, never Failed.

Halcyon's definition does not route a vendor body that answers these keys; not measured.
In the definition, `isEDRDeployed`, `isEPPDeployed` and `isEPPConfigured` are wired to the
`checkInstalled` method; this file does not read that response to answer them. The keys are
Unevaluated together because the evaluator reads one dataCollection status per response.

What this file did before:
coverage arithmetic over `items[*].assignedProducts` and `health.services.serviceDetails`,
plus `isEPPConfigured` answered from `data["isEPPConfigured"]` or a non-empty-collection
fallback. Nothing in Halcyon's definition shows that its body carries those fields.
"""

from datetime import datetime

KEYS = ("isEPPEnabled", "isEPPDeployed", "isEPPLoggingEnabled", "isEPPEnabledForCriticalSystems",
        "isEDRDeployed", "isEndpointSecurityEnabled", "isMDREnabled", "isMDRLoggingEnabled",
        "requiredCoveragePercentage", "requiredConfigurationPercentage", "isEPPConfigured")

REASON = "Not measured: Halcyon's definition does not route a vendor body that answers this key"


def create_response(result, api_errors, input_summary=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if api_errors else "success",
                "errors": api_errors or []
            },
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": [],
                "failReasons": api_errors or [],
                "recommendations": [],
                "additionalFindings": []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "epp_transform",
                "vendor": "Halcyon",
                "category": "Endpoint Security"
            }
        }
    }


def transform(input):
    # No body can change this answer, so the body is not read: a value that is always None
    # carries its error status with it, on every path including a body whose reads raise.
    result = {}
    for key in KEYS:
        result[key] = None
    return create_response(result, [REASON])
