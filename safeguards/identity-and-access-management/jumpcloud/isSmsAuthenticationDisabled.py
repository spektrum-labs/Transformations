"""
Transformation: isSmsAuthenticationDisabled
Vendor: JumpCloud  |  Category: Identity and Access Management

Criterion (isEquals true): "SMS is excluded from the set of permitted MFA factor types."

Data source: GET https://console.jumpcloud.com/api/v2/authn/policies (IS method listAuthnPolicies; JumpCloud API 2.0
"List Authentication Policies", scopes authn / authn.readonly). Spec: https://docs.jumpcloud.com/api/2.0/index.yaml,
schemas AuthnPolicy, AuthnPolicyEffect, AuthnPolicyObligations:
  * disabled, monitorOnly (booleans); effect.action: allow | deny | unknown
  * effect.obligations.mfa.required (boolean)
  * effect.obligations.mfaFactors: [{"type": DURT | WEBAUTHN | PUSH | DUO | TOTP | SMS_OTP}] -- OBJECTS, not strings.
    The previous version of this file matched string entries only, so it never saw an SMS factor and passed.

SMS in JumpCloud (https://jumpcloud.com/support/sms-mfa-configuration): "SMS One-Time Passcode" is an organisation-
level toggle (Security > MFA Configurations, Twilio Verify credentials), off until an admin enables it, and is chosen
per policy "via specific MFA factor selection through JumpCloud Conditional Access Policies". A policy with no
explicit factor list uses "All Enabled" (https://jumpcloud.com/support/choosing-multi-factor-authenticators-in-
conditional-access-policies); neither page says whether that includes SMS, and the organisation's MFA configuration
is not exposed by the API, so an "All Enabled" policy cannot show whether SMS is allowed.

A policy is ENFORCED when it is not disabled, not monitor-only, and its action is allow. Only enforced policies that
require MFA have an MFA factor set to judge.

Verdict:
  True   every enforced MFA-requiring policy has an explicit mfaFactors list, and none of them lists SMS_OTP.
  False  an enforced MFA-requiring policy lists SMS_OTP. This holds even if another policy is unreadable.
  None   (Unevaluated, dataCollection error) no evidence (null, {}, error/403 envelope, unrelated JSON, a partial read),
         no enforced MFA-requiring policy, a policy with an empty or missing factor list ("All Enabled"), a factor
         type outside the documented enum, or a field that cannot be read as a boolean. Never a pass.
"""
import json
from datetime import datetime

KEY = "isSmsAuthenticationDisabled"
META = {"transformationId": KEY, "vendor": "JumpCloud", "category": "identity-and-access-management"}
DOCUMENTED = ("DURT", "WEBAUTHN", "PUSH", "DUO", "TOTP", "SMS_OTP")


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


def unevaluated(problem, validation=None, summary=None):
    return create_response(result={KEY: None}, validation=validation, fail_reasons=[problem], api_errors=[problem],
                           input_summary=summary)


def as_bool(value, absent=None):
    """True/False for a JSON boolean or a "true"/"false" string; `absent` for None; else 'bad'."""
    if value is None:
        return absent
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return "bad"


def as_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def policy_list(data):
    """(policies, problem)."""
    if isinstance(data, list):
        policies = data
    elif isinstance(data, dict) and isinstance(data.get("results"), list):
        policies = data["results"]
        total = as_count(data.get("totalCount"))
        if total is not None and len(policies) < total:
            return None, ("Read " + str(len(policies)) + " of " + str(total) +
                          " JumpCloud authentication policies; a partial read is not evaluated.")
    else:
        return None, "No JumpCloud authentication policy list in the response; nothing to evaluate."
    if not all(isinstance(p, dict) and isinstance(p.get("effect"), dict) for p in policies):
        return None, "The response is not a list of JumpCloud authentication policies (each needs an effect)."
    return policies, None


def is_sms(factor_type):
    return "SMS" in factor_type


def judge(policy):
    """('skip' | 'sms' | 'no_sms' | 'undecided' | 'unreadable', reason)."""
    disabled = as_bool(policy.get("disabled"), absent=False)
    monitor = as_bool(policy.get("monitorOnly"), absent=False)
    if disabled == "bad" or monitor == "bad":
        return "unreadable", "disabled or monitorOnly is not a boolean"
    if disabled or monitor:
        return "skip", "not enforced"
    effect = policy["effect"]
    action = str(effect.get("action") or "").strip().lower()
    if action == "deny":
        return "skip", "deny policy"
    if action != "allow":
        return "unreadable", "effect.action is " + repr(effect.get("action"))
    obligations = effect.get("obligations") or {}
    if not isinstance(obligations, dict):
        return "unreadable", "effect.obligations is not an object"
    mfa = obligations.get("mfa") or {}
    required = as_bool(mfa.get("required") if isinstance(mfa, dict) else "bad", absent=False)
    if required == "bad":
        return "unreadable", "mfa.required is not a boolean"
    if not required:
        return "skip", "does not require MFA"
    factors = obligations.get("mfaFactors")
    if factors is None or factors == []:
        return "undecided", ("requires MFA with no explicit mfaFactors list ('All Enabled'); whether the organisation "
                             "has SMS One-Time Passcode enabled is not exposed by the JumpCloud API")
    if not isinstance(factors, list):
        return "unreadable", "mfaFactors is not a list"
    types = []
    for f in factors:
        t = f.get("type") if isinstance(f, dict) else f
        if not isinstance(t, str) or not t.strip():
            return "unreadable", "an mfaFactors entry has no type"
        types.append(t.strip().upper())
    if [t for t in types if is_sms(t)]:
        return "sms", "allows SMS one-time passcode (mfaFactors " + ", ".join(sorted(set(types))) + ")"
    unknown = [t for t in types if t not in DOCUMENTED]
    if unknown:
        return "undecided", "lists factor type(s) outside the documented enum: " + ", ".join(sorted(set(unknown)))
    return "no_sms", "allows " + ", ".join(sorted(set(types))) + " (no SMS)"


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        policies, problem = policy_list(data)
        if problem:
            return unevaluated(problem, validation)
        buckets = {"sms": [], "no_sms": [], "undecided": [], "unreadable": [], "skip": []}
        for p in policies:
            kind, reason = judge(p)
            name = str(p.get("name") or p.get("id") or "unnamed policy")
            buckets[kind].append("'" + name + "' " + reason)
        judged = len(buckets["sms"]) + len(buckets["no_sms"]) + len(buckets["undecided"]) + len(buckets["unreadable"])
        summary = {"totalPolicies": len(policies), "enforcedMfaPolicies": judged,
                   "policiesAllowingSms": len(buckets["sms"]), "policiesWithoutSms": len(buckets["no_sms"]),
                   "undecided": len(buckets["undecided"]), "unreadable": len(buckets["unreadable"]),
                   "skipped": len(buckets["skip"])}
        if buckets["sms"]:
            return create_response(
                result={KEY: False, "enforcedMfaPolicies": judged, "policiesAllowingSms": len(buckets["sms"])},
                validation=validation,
                fail_reasons=[str(len(buckets["sms"])) + " of " + str(judged) + " enforced JumpCloud MFA policies allow "
                              "SMS: " + "; ".join(buckets["sms"][:5])],
                recommendations=["Remove SMS One-Time Passcode from these conditional access policies' authenticators "
                                 "and use WebAuthn (or at least TOTP or Push) instead."],
                input_summary=summary)
        if buckets["unreadable"]:
            return unevaluated("JumpCloud authentication policies could not be read: " +
                               "; ".join(buckets["unreadable"][:5]), validation, summary)
        if buckets["undecided"]:
            return unevaluated("Whether SMS is allowed cannot be determined: " + "; ".join(buckets["undecided"][:5]) +
                               ". Selecting explicit authenticators on the policy makes this measurable.",
                               validation, summary)
        if not buckets["no_sms"]:
            return unevaluated("No enforced (enabled, not monitor-only) JumpCloud policy requires MFA, so no policy "
                               "shows which MFA factors are permitted.", validation, summary)
        return create_response(
            result={KEY: True, "enforcedMfaPolicies": judged, "policiesAllowingSms": 0},
            validation=validation,
            pass_reasons=["None of the " + str(judged) + " enforced JumpCloud MFA policies allows SMS; each has an "
                          "explicit authenticator list: " + "; ".join(buckets["no_sms"][:5])],
            input_summary=summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
