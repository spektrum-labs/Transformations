"""
Transformation: epp_transform
Vendor: Arctic Wolf - EDR Endpoint Security (Aurora Endpoint Defense API)
Category: Endpoint Security

NOT MEASURED. Every key below returns None with a dataCollection error, so it reads Unevaluated
-- never Passed, never Failed.

The Arctic Wolf - EDR Endpoint Security definition routes these keys to the
`checkInstalled` method, which has no request defined in that definition (no url, no HTTP
method), so no vendor body ever reaches this file.

The parse this file carried was written for Sophos Central: it counted `assignedProducts`
codes (endpointProtection, mtr, interceptX) and `health.services.serviceDetails`. The Aurora
Device API (Get devices extended, GET /devices/v2) returns `products`, `policy`, `state` and
`agent_version` per device and none of those Sophos fields, so an Aurora body would have
read 0% coverage. `isEPPConfigured` was answered from a field of its own name. The keys are
Unevaluated together because the evaluator reads one dataCollection status per response.

What this file did before:
Sophos-shaped coverage arithmetic, plus `isEPPConfigured` answered from
`data["isEPPConfigured"]` or a non-empty-collection fallback.

Docs: Aurora Endpoint Defense API, https://docs.arcticwolf.com/en/developer-and-oem/aurora-endpoint-defense-api
(retrieved 2026-10-07).
"""

from datetime import datetime

KEYS = ("isEPPEnabled", "isEPPDeployed", "isEPPLoggingEnabled", "isEPPEnabledForCriticalSystems",
        "isEDRDeployed", "isEndpointSecurityEnabled", "isMDREnabled", "isMDRLoggingEnabled",
        "requiredCoveragePercentage", "requiredConfigurationPercentage", "isEPPConfigured")

REASON = ("Not measured: this integration's checkInstalled method calls no Aurora endpoint, and the "
          "former parse read Sophos fields no Aurora API returns")


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
                "vendor": "Arctic Wolf",
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
