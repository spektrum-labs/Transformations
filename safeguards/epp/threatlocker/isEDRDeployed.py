"""Transformation: isEDRDeployed (ThreatLocker, method getComputers) -- NOT EVALUATED for every input.

ThreatLocker Detect is ThreatLocker's EDR module, but no documented PortalAPI field or endpoint exposes whether
Detect is licensed or enabled per computer or organisation (checked 2026-10-01: the threatlocker.kb.help API pages,
the public PortalAPI swagger, and an OpenAPI mirror of the official spec). The computer rows carry
`maintenanceCapabilities.detect` and `isOpsAlertsDisabled`, but both are undocumented, and an undocumented flag
cannot tell "Detect not licensed" (the customer's) from "licensed but off" (a finding).

So this transform returns isEDRDeployed None with dataCollection "error" for ALL inputs, so a False can never be
wired by mistake. Replace it when ThreatLocker documents a Detect source (for example the Detect policy routes the
Liongard inspector reads).
"""
from datetime import datetime

KEY = "isEDRDeployed"
REASON = "ThreatLocker Detect state is not exposed by a documented API field"


def transform(input):
    return {
        "transformedResponse": {KEY: None},
        "additionalInfo": {
            "dataCollection": {"status": "error", "errors": [REASON]},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": {}},
            "evaluation": {"passReasons": [], "failReasons": [REASON], "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": "ThreatLocker", "category": "epp"},
        },
    }
