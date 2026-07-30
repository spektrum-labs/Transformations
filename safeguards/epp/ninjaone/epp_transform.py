"""
Transformation: epp_transform (NinjaOne)
Vendor: NinjaOne
Category: Endpoint Security

Evaluates endpoint protection coverage from the NinjaOne antivirus status report:
  GET /api/v2/queries/antivirus-status  ->  { cursor, results: [ DeviceAntivirusStatus ] }

Each DeviceAntivirusStatus record (per the NinjaOne Public API 2.0 spec) carries:
  productName       - AV/EPP/EDR product reported on the device (e.g. "Microsoft Defender Antivirus")
  productState      - product state string (e.g. "ON" / "OFF" / "EXPIRED" / "SNOOZED")
  definitionStatus  - signature/definition freshness (e.g. "UP_TO_DATE" / "OUT_OF_DATE")
  version           - product version
  deviceId          - NinjaOne device identifier
  timestamp         - epoch seconds the data was collected

Emits:
  isEPPDeployed     - at least one device is reporting an active endpoint-protection product
  isEDRDeployed     - same signal (NinjaOne's antivirus-status does not distinguish EPP from EDR;
                      modern reported products are EDR-capable, so we mirror EPP rather than fabricate)
  isEPPConfigured   - protected devices also have up-to-date definitions
  requiredCoveragePercentage - % of AV-reporting devices that are actively protected

Note: antivirus-status only returns devices that report an AV product, so coverage is measured
relative to AV-reporting devices. Devices that report NO AV telemetry are surfaced via the
device inventory, not here.
"""

import json
from datetime import datetime


ACTIVE_STATES = {"on", "enabled", "active", "ok", "running", "started", "up_to_date"}
DISABLED_STATES = {"off", "disabled", "expired", "snoozed", "error", "stopped",
                   "not running", "not_running", "unknown", ""}
UP_TO_DATE = {"up_to_date", "uptodate", "up-to-date", "current", "ok", "good"}


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
                "transformationId": "epp_transform",
                "vendor": "NinjaOne",
                "category": "Endpoint Security"
            }
        }
    }


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isEPPDeployed": False, "isEDRDeployed": False, "isEPPConfigured": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        # NinjaOne antivirus-status returns { cursor, results: [...] }; tolerate list / data shapes too.
        records = []
        if isinstance(data, dict):
            if isinstance(data.get("results"), list):
                records = data["results"]
            elif isinstance(data.get("data"), list):
                records = data["data"]
        elif isinstance(data, list):
            records = data

        reporting_devices = set()
        protected_devices = set()
        configured_devices = set()
        outdated_devices = set()
        products = {}

        for rec in records:
            if not isinstance(rec, dict):
                continue
            device_id = rec.get("deviceId", rec.get("id"))
            if device_id is None:
                continue
            reporting_devices.add(device_id)

            product_name = str(rec.get("productName", "")).strip()
            product_state = str(rec.get("productState", "")).strip().lower()
            definition_status = str(rec.get("definitionStatus", "")).strip().lower()

            is_active = bool(product_name) and (
                product_state in ACTIVE_STATES or
                (product_state not in DISABLED_STATES)
            )

            if is_active:
                protected_devices.add(device_id)
                if product_name:
                    products[product_name] = products.get(product_name, 0) + 1
                if definition_status in UP_TO_DATE:
                    configured_devices.add(device_id)
                elif definition_status:
                    outdated_devices.add(device_id)

        total_reporting = len(reporting_devices)
        total_protected = len(protected_devices)
        total_configured = len(configured_devices)

        coverage = round((total_protected / total_reporting) * 100) if total_reporting > 0 else 0
        configured_pct = round((total_configured / total_protected) * 100) if total_protected > 0 else 0

        is_epp_deployed = total_protected > 0
        is_edr_deployed = is_epp_deployed
        # "Configured" requires protection AND that the majority of protected devices have current definitions.
        is_epp_configured = is_epp_deployed and total_configured > 0 and configured_pct >= 50

        if is_epp_deployed:
            product_list = ", ".join(sorted(products.keys())) if products else "an endpoint-protection product"
            pass_reasons.append(
                f"Endpoint protection active on {total_protected} of {total_reporting} "
                f"AV-reporting device(s) ({coverage}% coverage); products: {product_list}"
            )
            if outdated_devices:
                additional_findings.append(
                    f"{len(outdated_devices)} protected device(s) have out-of-date AV definitions"
                )
            if not is_epp_configured:
                recommendations.append(
                    "Ensure AV definitions are kept up to date on protected endpoints"
                )
        else:
            fail_reasons.append("No actively-protected endpoints found in NinjaOne antivirus status")
            recommendations.append(
                "Deploy and enable an antivirus/EDR product on managed endpoints in NinjaOne"
            )

        return create_response(
            result={
                "isEPPDeployed": is_epp_deployed,
                "isEDRDeployed": is_edr_deployed,
                "isEPPConfigured": is_epp_configured,
                "requiredCoveragePercentage": coverage,
                "devicesReporting": total_reporting,
                "protectedDevices": total_protected,
                "configuredDevices": total_configured,
                "definitionsUpToDatePercentage": configured_pct
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "devicesReporting": total_reporting,
                "protectedDevices": total_protected,
                "configuredDevices": total_configured,
                "products": products
            }
        )

    except Exception as e:
        return create_response(
            result={"isEPPDeployed": False, "isEDRDeployed": False, "isEPPConfigured": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
