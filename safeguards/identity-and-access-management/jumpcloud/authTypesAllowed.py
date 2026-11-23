"""
Transformation: authTypesAllowed
Vendor: JumpCloud  |  Category: Identity and Access Management

Criterion (isEquals true): only phishing-resistant authentication methods are allowed, for example
"Only phishing-resistant authentication methods are enabled; SMS and email OTP are disabled", or the
auth-methods half of a phishing-resistant MFA requirement for all users or for network services.

Data source: GET https://console.jumpcloud.com/api/v2/authn/policies (IS method listAuthnPolicies; JumpCloud
API 2.0 "List Authentication Policies", scopes authn / authn.readonly). Spec:
https://docs.jumpcloud.com/api/2.0/index.yaml, schemas AuthnPolicy, AuthnPolicyEffect, AuthnPolicyObligations:
  * disabled, monitorOnly (booleans); effect.action: allow | deny | unknown
  * effect.obligations.mfa.required (boolean)
  * effect.obligations.mfaFactors: [{"type": DURT | WEBAUTHN | PUSH | DUO | TOTP | SMS_OTP}] -- the documented
    field that holds the MFA factor types a policy allows. In the console a policy must "select at least one
    factor or select All Enabled"; with no explicit list it allows every factor enabled for the organisation,
    and the API does not expose that organisation-wide list.

A policy is ENFORCED when it is not disabled, not monitor-only, and its action is allow.
  * WEBAUTHN (FIDO2 security keys, platform authenticators, passkeys) is the only documented phishing-resistant
    factor type.
  * PUSH, DUO, TOTP and SMS_OTP are phishable (approve / one-time-code factors).
  * DURT, and any type not in the enum, has no documented meaning, so it is not counted either way.

Verdict:
  True   every enforced policy requires MFA and its explicit mfaFactors list holds only WEBAUTHN.
  False  an enforced policy allows sign-in without MFA (mfa.required false: password, or LDAP bind), or its
         explicit mfaFactors list includes a phishable factor. This holds even if another policy is unreadable.
  None   (Unevaluated, dataCollection error) no evidence (null, {}, error/403 envelope, unrelated JSON, a partial
         read), no enforced policy, an enforced policy that relies on "All Enabled" (no explicit factor list) or
         lists an undocumented factor type, or a field that cannot be read as a boolean.
Scope: authentication policies govern the user portal, admin portal, SSO applications and LDAP. A user that no
enforced policy targets is outside what this API can show.
"""
import json
from datetime import datetime

KEY = "authTypesAllowed"
META = {"transformationId": KEY, "vendor": "JumpCloud", "category": "identity-and-access-management"}
PHISHING_RESISTANT = ("WEBAUTHN",)
PHISHABLE = ("PUSH", "DUO", "TOTP", "SMS_OTP")


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
                    input_summary=None, api_errors=None, transformation_errors=None, additional_findings=None):
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
                           "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
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


def factor_types(obligations):
    """(list of upper-case factor types, problem)."""
    factors = obligations.get("mfaFactors")
    if factors is None:
        return [], None
    if not isinstance(factors, list):
        return None, "mfaFactors is not a list"
    out = []
    for f in factors:
        t = f.get("type") if isinstance(f, dict) else f
        if not isinstance(t, str) or not t.strip():
            return None, "an mfaFactors entry has no type"
        out.append(t.strip().upper())
    return out, None


def judge(policy):
    """('enforced' | 'skip' | 'unreadable', None) or ('pr' | 'phishable' | 'undecided', reason)."""
    disabled = as_bool(policy.get("disabled"), absent=False)
    monitor = as_bool(policy.get("monitorOnly"), absent=False)
    if disabled == "bad" or monitor == "bad":
        return "unreadable", "disabled or monitorOnly is not a boolean"
    if disabled or monitor:
        return "skip", None
    effect = policy["effect"]
    action = str(effect.get("action") or "").strip().lower()
    if action == "deny":
        return "skip", None
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
        return "phishable", "allows sign-in without MFA (mfa.required is not true)"
    types, problem = factor_types(obligations)
    if problem:
        return "unreadable", problem
    if not types:
        return "undecided", ("requires MFA but sets no explicit mfaFactors list ('All Enabled'); the organisation's "
                             "enabled factors are not exposed by the JumpCloud API")
    weak = [t for t in types if t in PHISHABLE]
    if weak:
        return "phishable", "allows phishable factor(s) " + ", ".join(sorted(set(weak)))
    unknown = [t for t in types if t not in PHISHING_RESISTANT]
    if unknown:
        return "undecided", "lists factor type(s) with no documented meaning: " + ", ".join(sorted(set(unknown)))
    return "pr", "requires MFA restricted to " + ", ".join(sorted(set(types)))


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
        buckets = {"pr": [], "phishable": [], "undecided": [], "unreadable": [], "skip": []}
        for p in policies:
            kind, reason = judge(p)
            name = str(p.get("name") or p.get("id") or "unnamed policy")
            buckets[kind].append(name if reason is None else "'" + name + "' " + reason)
        enforced = len(buckets["pr"]) + len(buckets["phishable"]) + len(buckets["undecided"]) + len(buckets["unreadable"])
        summary = {"totalPolicies": len(policies), "enforcedAllowPolicies": enforced,
                   "phishingResistantOnly": len(buckets["pr"]), "phishable": len(buckets["phishable"]),
                   "undecided": len(buckets["undecided"]), "unreadable": len(buckets["unreadable"]),
                   "skippedDisabledMonitorOrDeny": len(buckets["skip"])}
        if buckets["phishable"]:
            return create_response(
                result={KEY: False, "enforcedAllowPolicies": enforced, "phishablePolicies": len(buckets["phishable"])},
                validation=validation,
                fail_reasons=[str(len(buckets["phishable"])) + " of " + str(enforced) + " enforced JumpCloud "
                              "authentication policies allow a non-phishing-resistant method: " +
                              "; ".join(buckets["phishable"][:5])],
                recommendations=["Require MFA on every enforced JumpCloud conditional access policy and restrict its "
                                 "authenticators to WebAuthn (security keys, platform authenticators or passkeys)."],
                input_summary=summary)
        if buckets["unreadable"]:
            return unevaluated("JumpCloud authentication policies could not be read: " +
                               "; ".join(buckets["unreadable"][:5]), validation, summary)
        if buckets["undecided"]:
            return unevaluated("The allowed authentication methods cannot be determined: " +
                               "; ".join(buckets["undecided"][:5]) + ". Selecting explicit authenticators on the "
                               "policy makes this measurable.", validation, summary)
        if not buckets["pr"]:
            return unevaluated("No enforced (enabled, not monitor-only) JumpCloud allow policy, so no policy shows "
                               "which authentication methods are allowed.", validation, summary)
        return create_response(
            result={KEY: True, "enforcedAllowPolicies": enforced, "phishablePolicies": 0},
            validation=validation,
            pass_reasons=["All " + str(enforced) + " enforced JumpCloud authentication policies require MFA restricted "
                          "to phishing-resistant WebAuthn: " + "; ".join(buckets["pr"][:5])],
            input_summary=summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
