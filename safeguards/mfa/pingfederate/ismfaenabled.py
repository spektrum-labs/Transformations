"""
Transformation: isMFAEnabled
Vendor: PingFederate  |  Category: Multi-Factor Authentication
Evaluates: At least one MFA-type IdP adapter is configured
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAEnabled", "vendor": "PingFederate", "category": "Multi-Factor Authentication"}
        }
    }


# WHY THIS RETURNS "NOT EVALUATED" RATHER THAN A VERDICT
#
# This file classified adapters with `plugin_id in MFA_ADAPTER_PLUGINS` -- and MFA_ADAPTER_PLUGINS was never
# defined anywhere in it. The only imports are json and datetime. `evaluate()` wraps its body in
# a bare `except Exception`, so the NameError never surfaced: it was swallowed into
# {"isMFAEnabled": False, "error": "name 'MFA_ADAPTER_PLUGINS' is not defined"}.
#
# The effect was a silent always-False for every PingFederate tenant, with the Python error text
# leaking into the customer-visible failReasons. Measured by executing this file against a
# realistic /pf-admin-api/v1/idp/adapters body:
#     failReasons = ['isMFAEnabled check failed', "name 'MFA_ADAPTER_PLUGINS' is not defined"]
#
# THE LIST WAS NOT SIMPLY MISSING -- IT CANNOT CURRENTLY BE WRITTEN CORRECTLY.
# Researched 2026-10-05 against PingFederate config exports, the Admin API, and the official Ping
# Terraform provider. Verified pluginDescriptorRef.id values, each seen in a real export or
# official docs:
#     com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter      username+password
#     com.pingidentity.adapters.httpbasic.idp.HttpBasicIdpAuthnAdapter    username+password
#     com.pingidentity.adapters.identifierfirst.idp.IdentifierFirstAdapter  identifier only, not a factor
#     com.pingidentity.adapters.kerberos.KerberosAuthenticationAdapter    desktop SSO
#     com.pingidentity.adapters.pingid.PingIDAdapter                      MFA, but push/OTP: phishable
#     com.pingidentity.adapters.pingid.PingIDSDKAdapter                   MFA, phishable
#     com.pingidentity.adapters.opentoken.IdpAuthnAdapter                 token transport, not a factor
#     com.pingidentity.adapters.ldap.LdapAuthenticationAdapter            username+password
#     com.pingidentity.adapters.iovation.IovationIdpAdapter               device risk signal
#     com.pingidentity.pf.adapters.referenceid.IdpBackchannelReferenceAuthnAdapter  backchannel, not a factor
#
# NO verified identifier was found for ANY phishing-resistant adapter -- not FIDO2/WebAuthn, not
# X.509 certificate, not Composite. So a strong-factor allowlist cannot be populated, and a check
# that cannot reach True is not a check.
#
# DO NOT ADOPT integration_configs/docs/ping_federate/authtypesallowed_transform.py from the
# Integration-Service repo. Its identifiers are plausible-looking and wrong: it names
# "com.pingidentity.adapters.pingid.idp.PingIDAuthnAdapter" where the real one is
# "com.pingidentity.adapters.pingid.PingIDAdapter", and a GitHub-wide search for its FIDO2, TOTP,
# HOTP and OATH ids returns zero hits outside Spektrum's own repositories. Adopting it would not
# fix this bug, it would HIDE it -- the check would still never match, but silently, without the
# error string that currently reveals it is broken. This is the same failure mode as the JumpCloud
# check that searched for FIDO2/PIV/SMARTCARD values its vendor never emits.
#
# SEPARATELY, /idp/adapters is the wrong evidence for this claim even with a correct allowlist. It
# lists the adapters that are CONFIGURED, not the ones an authentication policy actually requires.
# A real implementation needs /pf-admin-api/v1/authenticationPolicies and the policy tree, plus a
# verified identifier set captured from a live tenant.
#
# Until both exist this answers "not evaluated", which is honest, rather than False, which was a
# finding against every customer.


def evaluate(data):
    """Deliberately returns no verdict. See the note above."""
    items = data.get("items") if isinstance(data, dict) else None
    count = len(items) if isinstance(items, list) else 0
    return {
        "isMFAEnabled": None,
        "adaptersReturned": count,
        "reason": ("PingFederate's adapter list (GET /pf-admin-api/v1/idp/adapters) shows which "
                   "adapters are configured, not which an authentication policy requires, and no "
                   "verified plugin identifier exists for any phishing-resistant PingFederate "
                   "adapter, so isMFAEnabled was not evaluated."),
    }


def transform(input):
    criteriaKey = "isMFAEnabled"
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
                fail_reasons=["Input validation failed, so this was not evaluated."]
            )

        # Run core evaluation
        eval_result = evaluate(data)

        # Extract the boolean result and any extra fields
        result_value = eval_result.get(criteriaKey, None)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value is None:
            # Not evaluated: say why, in the customer's words, and do not recommend a fix for a
            # finding we have not actually made.
            fail_reasons.append(str(eval_result.get("reason") or
                                    f"{criteriaKey} was not evaluated."))
        elif result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review PingFederate configuration for {criteriaKey}")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
