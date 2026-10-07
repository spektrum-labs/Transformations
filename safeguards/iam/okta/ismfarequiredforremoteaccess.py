# ismfarequiredforremoteaccess.py - Okta Identity Engine
#
# Method: workflow getRemoteAccessMfaPolicies (Integration-Service), three existing GET methods:
#   listApplications -> applications   GET /api/v1/apps?limit=200   (okta.apps.read, reportPagination)
#   getAccessPolicy  -> accessPolicies GET /api/v1/policies?type=ACCESS_POLICY      (okta.policies.read)
#   listPolicyRules  -> accessRules    GET /api/v1/policies/{policyId}/rules, one list per policy, same order
# Both scopes are already granted for isLifeCycleManagementEnabled / isSAMLEnforced (apps) and
# isMFAEnforcedForUsers / isMFAEnforcedForAdmins (policies). No new scope, no write.
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Application/
#       https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
#   Application._links.accessPolicy.href -> the authentication policy that gates sign-in to the app.
#   AccessPolicyRule.actions.appSignOn.{access, verificationMethod.{type, factorMode}}
#
# WHICH APPS ARE "REMOTE ACCESS". Okta speaks here only for the remote-access apps it fronts. An app
# is a remote-access app when it is one of these, and never because of its label (labels are chosen
# by the customer and prove nothing):
#   1. Okta Integration Network catalog app key ``name`` in REMOTE_ACCESS_CATALOG_NAMES. The key is
#      set by Okta's catalog, not by the customer: "aws_clientvpn" is Okta's AWS Client VPN app.
#   2. A custom SAML 2.0 app whose service provider is AWS Client VPN, read from its SAML settings:
#      audience (SP entity ID) "urn:amazon:webservices:clientvpn", or the Client VPN assertion
#      consumer URLs (the desktop client's local listener, or the self-service portal), as published
#      in the AWS Client VPN administrator guide, "SAML-based federated authentication".
# Extending to another VPN or remote-desktop product means adding its catalog key or SAML service
# provider identifiers here, with the vendor document that defines them.
#
# Okta MFA-as-a-service apps (for example RDP or ADFS MFA, signOnMode MFA_AS_SERVICE) have no
# authentication policy link; they are not judged here.


def transform(input):
    """
    isMFARequiredForRemoteAccess - True only when Okta fronts at least one ACTIVE remote-access app
    (see the header) and, for every such app, the authentication policy linked to it is returned,
    is ACTIVE, has at least one ACTIVE rule that ALLOWs access, and every ACTIVE ALLOW rule requires
    verificationMethod type ASSURANCE with factorMode 2FA.

    Rule conditions (network zone, group, device) are ignored on purpose: a single-factor rule scoped
    to one network or one group is still a single-factor path into the remote-access app.

    Returns None (not evaluated, dataCollection.status "error") when nothing can be judged: an error
    body, missing or misaligned lists, a truncated app list, no ACTIVE remote-access app in Okta (this
    tool does not front remote access, so it has no answer), or a remote-access app whose policy or
    rules were not returned. Returns False when any judged app has an ALLOW rule that does not demand
    two factors, including a verification method this code does not recognise.

    Also returns remoteAccessApps (ACTIVE remote-access apps found) and remoteAccessAppsWithoutMFA
    (those with a rule that does not demand two factors), as numbers.

    Does not prove: which authenticators satisfy the second factor, that the VPN itself accepts only
    SAML sign-in (that is the VPN endpoint's setting, read on the cloud side), or anything about
    remote-access paths that do not sign in through Okta.
    """
    import json
    from datetime import datetime, timezone

    key = "isMFARequiredForRemoteAccess"
    catalog_names = ["aws_clientvpn"]
    saml_audiences = ["urn:amazon:webservices:clientvpn"]
    saml_acs_urls = ["http://127.0.0.1:35001",
                     "https://self-service.clientvpn.amazonaws.com/api/auth/sso/saml"]

    def as_text(value):
        if value is None:
            return ""
        return str(value).strip()

    def as_dict(value):
        if isinstance(value, dict):
            return value
        return {}

    def respond(value, apps, weak_apps, passes, fails, summary, errors):
        return {
            "transformedResponse": {key: None if errors else value,
                                    "remoteAccessApps": apps,
                                    "remoteAccessAppsWithoutMFA": weak_apps},
            "additionalInfo": {
                "dataCollection": {"status": "error" if errors else "success", "errors": errors},
                "validation": {"status": "unknown", "errors": [], "warnings": []},
                "transformation": {"status": "success", "errors": [], "inputSummary": summary},
                "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": [],
                               "additionalFindings": []},
                "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                             "transformationId": key, "vendor": "Okta",
                             "category": "Identity and Access Management"},
            },
        }

    def not_evaluated(reason, apps=0, summary=None):
        return respond(None, apps, 0, [], [reason], summary or {}, [reason])

    def unwrap_list(value):
        while isinstance(value, dict):
            inner = None
            for wrapper in ["apiResponse", "response", "result", "data"]:
                if wrapper in value:
                    inner = value[wrapper]
                    break
            if inner is None:
                break
            value = inner
        return value

    def is_remote_access(app):
        if as_text(app.get("name")).lower() in catalog_names:
            return True
        if as_text(app.get("signOnMode")).upper() != "SAML_2_0":
            return False
        sign_on = as_dict(as_dict(app.get("settings")).get("signOn"))
        for field in ["audience", "audienceOverride"]:
            if as_text(sign_on.get(field)).lower() in saml_audiences:
                return True
        for field in ["ssoAcsUrl", "ssoAcsUrlOverride"]:
            if as_text(sign_on.get(field)).lower().rstrip("/") in saml_acs_urls:
                return True
        return False

    def policy_id_of(app):
        link = as_dict(as_dict(app.get("_links")).get("accessPolicy"))
        href = as_text(link.get("href")).rstrip("/")
        if "/policies/" not in href:
            return ""
        return href.split("/policies/")[-1].split("?")[0]

    try:
        data = input
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        if isinstance(data, str):
            data = json.loads(data)
        for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
            if isinstance(data, dict) and wrapper in data and "applications" not in data:
                data = data[wrapper]
        if not isinstance(data, dict):
            return not_evaluated("Response is not an object with application, policy and rule lists")
        for k in ["errorCode", "errorSummary", "error", "errors", "errorMessage"]:
            if data.get(k):
                return not_evaluated("Okta returned an error: " + as_text(data.get(k))[:200])

        apps = unwrap_list(data.get("applications"))
        policies = unwrap_list(data.get("accessPolicies"))
        rules = data.get("accessRules")
        if not isinstance(apps, list):
            return not_evaluated("Application list is missing")
        if data.get("paginationTruncated") is True:
            return not_evaluated("The application list was truncated, so not every app was read")
        if not isinstance(policies, list):
            return not_evaluated("Authentication (ACCESS_POLICY) policy list is missing")
        if not isinstance(rules, list) or len(rules) != len(policies):
            return not_evaluated("Authentication policy rule lists are missing or do not line up with the policies")

        by_id = {}
        for index in range(len(policies)):
            policy = policies[index]
            if isinstance(policy, dict) and as_text(policy.get("id")):
                by_id[as_text(policy.get("id"))] = index

        remote = []
        inactive_remote = 0
        for app in apps:
            if not isinstance(app, dict) or not is_remote_access(app):
                continue
            if as_text(app.get("status")).upper() == "ACTIVE":
                remote.append(app)
            else:
                inactive_remote = inactive_remote + 1

        summary = {"applicationsRead": len(apps), "remoteAccessApps": len(remote),
                   "inactiveRemoteAccessApps": inactive_remote}
        if not remote:
            return not_evaluated("No ACTIVE remote-access app (AWS Client VPN) signs in through Okta, "
                                 "so Okta does not speak for remote access here", 0, summary)

        judged = []
        weak = []
        unmeasured = []
        no_access = []
        for app in remote:
            label = as_text(app.get("label")) or as_text(app.get("id"))
            policy_id = policy_id_of(app)
            if not policy_id or policy_id not in by_id:
                unmeasured.append(label + " (authentication policy not returned)")
                continue
            index = by_id[policy_id]
            policy = policies[index]
            if as_text(policy.get("status")).upper() != "ACTIVE":
                unmeasured.append(label + " (authentication policy is not ACTIVE)")
                continue
            policy_rules = unwrap_list(rules[index])
            if not isinstance(policy_rules, list):
                unmeasured.append(label + " (policy rules unreadable)")
                continue
            allow = 0
            single = []
            for rule in policy_rules:
                if not isinstance(rule, dict) or as_text(rule.get("status")).upper() != "ACTIVE":
                    continue
                sign_on = as_dict(as_dict(rule.get("actions")).get("appSignOn"))
                if as_text(sign_on.get("access")).upper() != "ALLOW":
                    continue
                allow = allow + 1
                method = as_dict(sign_on.get("verificationMethod"))
                method_type = as_text(method.get("type")).upper()
                mode = as_text(method.get("factorMode")).upper()
                if not (method_type == "ASSURANCE" and mode == "2FA"):
                    single.append(as_text(rule.get("name")) + " (" + (method_type or "no method") + " / "
                                  + (mode or "no factorMode") + ")")
            if allow == 0:
                no_access.append(label)
                continue
            judged.append(label + " via policy '" + as_text(policy.get("name")) + "' (" + str(allow)
                          + " ALLOW rule(s))")
            if single:
                weak.append(label + ": " + ", ".join(single[:5]))

        summary["judgedApps"] = len(judged)
        summary["appsWithoutMFA"] = len(weak)
        summary["unmeasuredApps"] = len(unmeasured)
        summary["appsWithNoAllowRule"] = len(no_access)

        if weak:
            return respond(False, len(remote), len(weak), [],
                           ["Remote-access sign-in through Okta accepts less than two factors: " + "; ".join(weak[:10])],
                           summary, [])
        if unmeasured:
            return not_evaluated("Authentication policy could not be read for remote-access app(s): "
                                 + "; ".join(unmeasured[:10]), len(remote), summary)
        if not judged:
            return not_evaluated("No remote-access app has an ACTIVE rule that allows sign-in, so no "
                                 "MFA requirement can be shown", len(remote), summary)
        return respond(True, len(remote), 0,
                       ["Every ACTIVE ALLOW rule requires two factors for " + str(len(judged))
                        + " remote-access app(s): " + "; ".join(judged[:10])],
                       [], summary, [])
    except Exception as e:
        return not_evaluated("Transformation error: " + str(e))
