"""
Transformation: isAttachmentSandboxDetonationEnabled
Vendor: Check Point Harmony Email & Collaboration (Check Point Email Security)
Method: queryEvents (security events)

NOT MEASURABLE FROM THIS DATA: the criterion is always None (Not evaluated), never True and never
False.

This check used to read True when any security event mentioned "sandbox", "emulat", "threatcloud",
"detonat" or "zero-day" in a free-text field, and False when no such event existed. A keyword in a
description does not measure a setting: it passed for a tenant whose attachment sandboxing (Threat
Emulation) was off, and it failed a tenant that simply had no events yet.

What the public Check Point Email Security API exposes (API Reference Guide, "Get the Details of a
Specific Entity" and "Search for Secured Entities"): entitySecurityResults and combinedVerdict carry
the scan results of five engines only, ap, dlp, clicktimeProtection, shadowIt and av. There is no
threat-emulation or sandbox result, no policy or security-engine endpoint and no licence endpoint.
The Anti-Malware engine bundles Anti-Virus with Threat Emulation, and whether a tenant has Threat
Emulation or Anti-Virus alone is visible only in the admin console (Security Settings, Security
Engines, Anti-Malware). Security events exist only after a detection. So an event list, empty or
not, cannot show whether attachments are sandboxed, and the av verdict (isAntivirusVerdictEngineEnabled
in checkpoint-harmony-email) cannot tell Anti-Virus alone from Anti-Virus plus Threat Emulation.

Each tool measures for that tool. A Check Point row for attachment sandboxing appears only when the
API exposes a real field. Until then this check reports Not evaluated: the criterion is None and
dataCollection.status is "error", which the evaluator shows as Not evaluated and which opens no gap.
The reason text is fixed; the vendor's own error text is never copied into it.
"""
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


KEY = "isAttachmentSandboxDetonationEnabled"

READ_FAILED = (
    "The Check Point security-event read returned an error, an empty body or a shape that is not "
    "an event list, so nothing was read; nothing to measure."
)

NOT_EXPOSED = (
    "Check Point's Email Security API does not expose whether attachment sandboxing (Threat "
    "Emulation) is on: scan results cover only the ap, dlp, clicktimeProtection, shadowIt and av "
    "engines, and there is no policy, security-engine or licence endpoint. A security event that "
    "mentions a sandbox, or an empty event list, does not show the setting; nothing to measure."
)


def not_measured(reason, validation, extra_result=None, input_summary=None, transformation_errors=None):
    """No verdict: the criterion is None and dataCollection.status is error, so the evaluator shows
    Not evaluated instead of a failed check. extra_result carries a fact that was really read (the
    number of events) next to the missing verdict."""
    result = {KEY: None}
    if extra_result:
        result.update(extra_result)
    return create_response(
        result=result,
        validation=validation,
        fail_reasons=[reason],
        input_summary=input_summary,
        transformation_errors=transformation_errors,
        api_errors=[reason],
        metadata={
            "transformationId": KEY,
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )


def read_failed(data):
    """True when the body is an error, an authentication failure or not an event list."""
    if not isinstance(data, dict):
        return True
    if data.get("error") or data.get("errorType") == "authentication" or data.get("statusCode") == 401:
        return True
    if data.get("statusCode") == 403 or data.get("status_code") in (401, 403):
        return True
    envelope = data.get("responseEnvelope")
    if isinstance(envelope, dict):
        code = envelope.get("responseCode")
        if code is not None and str(code) not in ("0", "200"):
            return True
    return not isinstance(data.get("responseData"), list)


def transform(input):
    try:
        data, validation = extract_input(input)
        if read_failed(data):
            return not_measured(READ_FAILED + " " + NOT_EXPOSED, validation)
        events = [ev for ev in data.get("responseData") if isinstance(ev, dict)]
        total_events = len(events)
        return not_measured(
            NOT_EXPOSED,
            validation,
            extra_result={"totalEventsQueried": total_events},
            input_summary={"totalEvents": total_events},
        )
    except Exception:
        return not_measured(
            READ_FAILED + " " + NOT_EXPOSED,
            None,
            transformation_errors=["The transformation could not read the body."],
        )
