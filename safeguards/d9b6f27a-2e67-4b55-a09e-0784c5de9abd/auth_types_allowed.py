"""
Transformation: authTypesAllowed
Vendor: Microsoft
Category: Identity / Authentication

Evaluates "no weak factors": only strong authentication methods are enabled (FIDO2, certificate-based
authentication, Microsoft Authenticator, software or hardware OATH tokens, and a Temporary Access Pass
with a maximum lifetime). SMS, voice and email OTP targeted at members fail. A method enabled with an
empty includeTargets list targets nobody and is not counted at all. An external method alone, or no
member method at all, is not evaluated.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                "transformationId": "authTypesAllowed",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "authTypesAllowed"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        # A body that decodes to nothing carries no evidence either way.
        if data in (None, {}, [], ""):
            return create_response(
                result={criteriaKey: False},
                validation={"status": "error", "errors": ["the vendor returned no data to evaluate"], "warnings": []},
                api_errors=["the vendor returned no data to evaluate"],
            )

        legacy_status = data.get("status", "unknown").lower()

        if validation.get("status") == "failed" or legacy_status in ["failed", "error"]:
            if legacy_status in ["failed", "error"] and isinstance(data, dict) and data.get("message"):
                fail_msg = str(data["message"])
            elif legacy_status in ["failed", "error"]:
                fail_msg = "Input indicated failure or error"
            else:
                fail_msg = "Input validation failed"
            return create_response(
                result={criteriaKey: False, "authTypes": []},
                validation=validation,
                fail_reasons=[fail_msg]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # FAIL CLOSED ON A BODY THAT IS NOT THE POLICY. This used to default
        # `authenticationMethodConfigurations` to `[]`, and "no insecure authentication
        # method is enabled" is vacuously true of the empty set -- so a Graph error envelope,
        # a 401/403, or a response to some other call produced zero enabled methods and
        # reported the criterion satisfied.
        #
        # The shape read is Microsoft Graph GET /v1.0/policies/authenticationMethodsPolicy,
        # whose 200 body carries `authenticationMethodConfigurations` as an array of
        # configuration objects, each with `id` and `state` ("enabled"/"disabled")
        # (https://learn.microsoft.com/en-us/graph/api/authenticationmethodspolicy-get).
        # Graph returns a configuration object for every method it knows about, enabled or
        # not, so an empty array means this is not the policy. Anything without a non-empty
        # array routes to dataCollection.status="error": the policy was never read, so the
        # absence of an insecure method is not evidence that none is enabled.
        auth_configs = data.get('authenticationMethodConfigurations') if isinstance(data, dict) else None
        if not isinstance(auth_configs, list) or not auth_configs:
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                api_errors=[("no authenticationMethodConfigurations array in the "
                             "authenticationMethodsPolicy response: the authentication "
                             "methods policy was never read, so the absence of an insecure "
                             "method is not evidence that none is enabled")])

        # Classify each enabled method (Graph authenticationMethodConfiguration objects).
        #
        # Rules (2026-10-03 fleet check, integration-fix-queue
        # changes/2026-10-03-false-fail-check, with J.J.'s decisions of 3 Oct 00:55 ET):
        #  * A method that is enabled but whose includeTargets list is EMPTY targets nobody,
        #    so it is not counted -- neither weak nor strong. (Josh's decision, 5 Oct 2026,
        #    superseding the 3 Oct rule that zero-target Email OTP fails.) Both shapes occur
        #    in real tenants -- Email enabled with empty includeTargets, and Email targeted at
        #    all_users or a group -- so the check still fails every tenant where a member can
        #    actually use email OTP. Removing a zero-target method can leave nothing enabled;
        #    that falls to the "no member method" rule below and is not evaluated -- which is
        #    also correct on its own terms, since tenants in that position are typically at
        #    policyMigrationState migrationInProgress, where legacy per-user MFA governs.
        #    The B2B guest email-OTP path the 3 Oct rule worried about is kept as an
        #    additional finding when allowExternalIdToUseEmailOtp is explicitly "enabled" (an
        #    admin choice), and not raised when it is "default" (Microsoft's tenant default).
        #    "default" is NOT "off": Microsoft turned guest email OTP on automatically for
        #    tenants left at default from October 2021, so guests can usually still use it.
        #    It is left out on purpose because it is not an admin choice; "disabled" means
        #    nobody, guests included, can use the method.
        #    Every zero-target method that would otherwise be classed as weak is still named
        #    in additionalFindings, so a lost target list (a $select, a proxy, a Graph shape
        #    change) that turns a weak method into a pass is visible in the evaluation.
        #    Only a PRESENT and EMPTY list counts as targeting nobody; a missing
        #    includeTargets key is unknown, not empty, and the method is still classified.
        #  * An external authentication method (for example Cisco Duo) enforces its own
        #    factors, which Entra cannot see. It is never called insecure here; when it is
        #    the only thing standing between "no weak method" and a verdict, the check is
        #    not evaluated (same rule as entra_strongauth_methods.py).
        #  * A Temporary Access Pass with a maximum lifetime is a time-limited onboarding
        #    and recovery credential, not a standing sign-in factor. It does not fail the
        #    check on its own or together with other allowed methods.
        #  * When no member method is enabled at all, the converged policy is not what
        #    governs sign-in (policyMigrationState preMigration / migrationInProgress, or
        #    legacy per-user MFA). That is not evidence either way: not evaluated, and the
        #    reason names policyMigrationState when the policy carries it.
        #  * X509Certificate (certificate-based authentication) and HardwareOath (OATH
        #    hardware tokens) are strong factors and are allowed.
        def targets_nobody(m):
            targets = m.get('includeTargets')
            return isinstance(targets, list) and not targets

        switched_on = [obj for obj in auth_configs
                       if isinstance(obj, dict) and str(obj.get('state', '')).lower() == "enabled"]
        zero_target = [m for m in switched_on if targets_nobody(m)]
        enabled_methods = [m for m in switched_on if not targets_nobody(m)]

        allowed_methods = ['fido2', 'x509certificate', 'microsoftauthenticator', 'softwareoath', 'hardwareoath']

        def method_id(m):
            return str(m.get('id', '') or '').lower()

        def is_external(m):
            return "externalauthenticationmethodconfiguration" in str(m.get('@odata.type') or '').lower()

        def bounded_tap(m):
            if method_id(m) != 'temporaryaccesspass':
                return False
            try:
                return int(m.get('maximumLifetimeInMinutes')) > 0
            except (ValueError, TypeError):
                return False

        allowed, weak, external, taps = [], [], [], []
        for m in enabled_methods:
            if is_external(m):
                external.append(str(m.get('displayName') or m.get('id') or 'external method'))
            elif bounded_tap(m):
                taps.append(m)
            elif method_id(m) in allowed_methods:
                allowed.append(m)
            else:
                weak.append(m)

        zero_target_weak = [m for m in zero_target
                            if not is_external(m) and not bounded_tap(m) and method_id(m) not in allowed_methods]
        zero_target_email = [m for m in zero_target if method_id(m) == 'email']
        guest_otp_chosen = [m for m in zero_target_email
                            if str(m.get('allowExternalIdToUseEmailOtp') or '').lower() == 'enabled']
        has_fido2 = any(method_id(m) == 'fido2' for m in enabled_methods)
        has_ms_auth = any(method_id(m) == 'microsoftauthenticator' for m in enabled_methods)
        migration = str(data.get('policyMigrationState') or '')
        input_summary = {
            "totalEnabledMethods": len(enabled_methods),
            "insecureMethods": len(weak),
            "hasFido2": has_fido2,
            "hasMsAuth": has_ms_auth,
            "externalMethods": external,
            "zeroTargetMethodsIgnored": [str(m.get('id') or '')[:60] for m in zero_target],
            "guestOnlyEmailOtp": any(str(m.get('allowExternalIdToUseEmailOtp') or '').lower() != 'disabled'
                                     for m in zero_target_email),
            "temporaryAccessPassBounded": bool(taps),
            "policyMigrationState": migration,
        }
        findings = []
        if taps:
            findings.append("Temporary Access Pass is enabled with a maximum lifetime (onboarding/recovery credential)")
        for m in zero_target_weak:
            findings.append(f"{str(m.get('id') or 'unknown')[:60]} is enabled but targets no users "
                            "(includeTargets is empty); not counted")
        if guest_otp_chosen:
            findings.append("Email one-time passcode is enabled for external (B2B guest) users "
                            "(allowExternalIdToUseEmailOtp is set to enabled). It targets no members, so it "
                            "does not affect this check, but guests can sign in with an emailed code.")

        if weak:
            insecure_names = [str(m.get('id', 'unknown'))[:60] for m in weak]
            fail_reasons.append(f"Insecure authentication methods enabled: {', '.join(insecure_names)}")
            recommendations.append("Disable SMS, voice and email OTP for members; use FIDO2/passkeys, "
                                   "certificate-based authentication, Microsoft Authenticator or OATH tokens")
            return create_response(
                result={criteriaKey: False, "authTypes": weak},
                validation=validation, pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                recommendations=recommendations, input_summary=input_summary, additional_findings=findings)

        if external:
            return create_response(
                result={criteriaKey: False},
                validation=validation, input_summary=input_summary, additional_findings=findings,
                api_errors=["No weak Microsoft method is enabled; the external authentication method(s) "
                            + ", ".join(e[:60] for e in external)
                            + " enforce their own factors and cannot be graded from Entra"])

        if not allowed:
            reason = "No member authentication method is enabled in the authentication methods policy"
            if migration.lower() in ("premigration", "migrationinprogress"):
                reason += (f" (policyMigrationState: {migration[:40]}): the legacy MFA and SSPR policies "
                           "still apply and cannot be read here")
            elif migration:
                reason += (f" (policyMigrationState: {migration[:40]}): the methods members can use are not "
                           "set by this policy, so it is not evidence either way")
            else:
                reason += ": the methods members can use are not set by this policy, so it is not evidence either way"
            if zero_target:
                reason += ("; enabled but targeting no one, so not counted: "
                           + ", ".join(str(m.get('id') or '')[:60] for m in zero_target))
            return create_response(
                result={criteriaKey: False},
                validation=validation, input_summary=input_summary, additional_findings=findings,
                api_errors=[reason])

        pass_reasons.append("Only allowed authentication methods are enabled: "
                            + ", ".join(str(m.get('id'))[:60] for m in allowed))
        return create_response(
            result={criteriaKey: True, "authTypes": []},
            validation=validation, pass_reasons=pass_reasons, input_summary=input_summary,
            additional_findings=findings)

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "authTypes": []},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
