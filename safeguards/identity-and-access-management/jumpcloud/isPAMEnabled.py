"""
Transformation: isPAMEnabled
Vendor: JumpCloud  |  Category: Identity and Access Management

Criterion (isEquals true): a privileged access management (PAM) solution is enabled.

Data source: GET https://console.jumpcloud.com/api/v2/privileged-access/status (IS method
getPrivilegedAccessStatus; JumpCloud API 2.0 operation PrivilegedAccessService_GetPasswordVaultStatus, tag
"Privileged Access", scopes pam / pam.readonly and the other pam.* scopes). Spec:
https://docs.jumpcloud.com/api/2.0/index.yaml, schema jumpcloud.privileged_access.GetPasswordVaultStatusResponse:
  * isPam (boolean): "True when the tenant has PAM activated."
  * isPwm (boolean): "True when the tenant has PWM (password vault) activated." -- a password manager, not PAM.
  * isActive (boolean, undocumented meaning)

Verdict:
  True   isPam is true (and isActive is not false): JumpCloud Privileged Access is activated for the tenant.
  False  isPam is false: JumpCloud's PAM is not activated. A password vault alone (isPwm) is not PAM.
  None   (Unevaluated, dataCollection error) null, {}, an error/401/403 envelope (for example an API key whose
         administrator has no Privileged Access scope), a body without a boolean isPam, or isPam true with
         isActive false (activated but not active is contradictory, so nothing is claimed).
What this does NOT show: which admin and service accounts the PAM manages, or how often their passwords rotate.
"""
import json
from datetime import datetime

KEY = "isPAMEnabled"
META = {"transformationId": KEY, "vendor": "JumpCloud", "category": "identity-and-access-management"}


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    metadata.update(META)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": metadata,
        },
    }


def unevaluated(problem, validation=None):
    return create_response(result={KEY: None}, validation=validation, fail_reasons=[problem], api_errors=[problem])


def as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if not isinstance(data, dict) or "isPam" not in data:
            return unevaluated("No JumpCloud Privileged Access status (isPam) in the response; nothing to evaluate.",
                               validation)
        is_pam = as_bool(data.get("isPam"))
        if is_pam is None:
            return unevaluated("JumpCloud Privileged Access status isPam is not a boolean.", validation)
        is_active = as_bool(data.get("isActive")) if "isActive" in data else None
        is_pwm = as_bool(data.get("isPwm")) if "isPwm" in data else None
        # Summary keys are our own names, not the vendor's field names: the verdict is the only
        # criterion this transform emits, and it must never be a field read back out of the body.
        summary = {"privilegedAccessActivated": is_pam, "tenantActive": is_active,
                   "passwordVaultActivated": is_pwm}
        if is_pam and is_active is False:
            return unevaluated("JumpCloud reports PAM activated (isPam true) but the tenant not active (isActive "
                               "false); nothing is claimed.", validation)
        if is_pam:
            return create_response(
                result={KEY: True}, validation=validation,
                pass_reasons=["JumpCloud Privileged Access (PAM) is activated for the tenant "
                              "(GET /api/v2/privileged-access/status isPam=true). This shows PAM is enabled; it does "
                              "not show which admin or service accounts it manages or their rotation schedule."],
                input_summary=summary)
        pwm_note = " A JumpCloud password vault is activated (isPwm=true), but a password manager is not PAM." if is_pwm else ""
        return create_response(
            result={KEY: False}, validation=validation,
            fail_reasons=["JumpCloud Privileged Access (PAM) is not activated for the tenant "
                          "(GET /api/v2/privileged-access/status isPam=false)." + pwm_note],
            recommendations=["Activate JumpCloud Privileged Access, or attest the PAM tool that manages admin and "
                             "service account credentials."],
            input_summary=summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
