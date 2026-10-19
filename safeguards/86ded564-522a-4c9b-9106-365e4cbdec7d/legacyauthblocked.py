"""
Transformation: legacyAuthBlocked
Vendor: Microsoft Entra ID  |  Category: Multifactor Authentication
Evaluates: Whether legacy authentication protocols are blocked

Legacy clients are the Conditional Access clientAppTypes exchangeActiveSync and other (POP, IMAP, SMTP AUTH and
other basic-auth protocols). True when at least one enabled policy blocks them.

Input: GET /v1.0/identity/conditionalAccess/policies. The Azure MFA workflow may merge
GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy into the same body under "securityDefaults" (the policy
list stays at the top, so a transform that does not know the key reads the same list). The keyed shape
{"conditionalAccessPolicies": ..., "securityDefaults": ...} is read too.

Security Defaults (Entra MFA review): when that read shows isEnabled true, Microsoft blocks legacy authentication for
every account, so the key is True whatever the policy list holds (Conditional Access cannot be enabled alongside
Security Defaults). A Security Defaults read that is absent, refused or unreadable changes nothing.

Not evaluated (value None, dataCollection.status "error"; Entra MFA review, decision 16 Oct 2026): a policy list that was
not read is not evidence that nothing blocks legacy clients, so these never read False:
- an error envelope, a refused read (vendorErrorAsResponse), a workflow step error, input validation failure, or a
  body with no policy list;
- an empty list: a tenant with no Conditional Access policy may block legacy authentication through Security
  Defaults (not read, or read as off) or Exchange Online authentication policies (not read);
- a policy that is not an object;
- a partial list (@odata.nextLink still present or paginationTruncated) with no blocking policy on the pages read.
False stays only when the whole list was read, holds at least one policy, and no enabled policy blocks legacy
clients.

Named evidence (#101): the reasons name the accounts the block does not reach, capped at 20 plus "and N more":
every user, group and directory role named in an enabled blocking policy that no blocking policy covers (a policy
covers a principal when it includes it, directly or through All users, and does not exclude it), and the user,
group or role scope when no blocking policy targets all users. Coverage is computed on the ids as the policies
list them; group and role membership is not expanded. Microsoft Graph returns object ids, not names, so the
reasons carry ids prefixed with their kind.

Names from the payload (tracker row 61, no extra call): a directory role is a role TEMPLATE id that is the same in
every tenant, so a built-in role is shown with its name (ROLE_NAMES, from Microsoft's "Microsoft Entra built-in
roles" reference). Each named exemption also says which blocking policy excludes it, by the policy's displayName.
User and group names are not in the Conditional Access payload and are not looked up. The id lists in
inputSummary are unchanged.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "legacyAuthBlocked", "vendor": "Microsoft Entra ID", "category": "Multifactor Authentication"}
        }
    }


MAX_NAMED = 20
LEGACY_CLIENTS = ['exchangeActiveSync', 'other']
EXCLUDE_FIELDS = [('excludeUsers', 'user'), ('excludeGroups', 'group'), ('excludeRoles', 'role')]
INCLUDE_FIELDS = [('includeUsers', 'user'), ('includeGroups', 'group'), ('includeRoles', 'role')]
# Graph keywords, not principals.
SPECIAL_PRINCIPALS = {'user:All', 'user:None', 'user:GuestsOrExternalUsers', 'group:All', 'role:All'}
MAX_POLICY_NAME = 60
# Built-in directory role template ids (the same in every tenant), from
# https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
ROLE_NAMES = {
    '62e90394-69f5-4237-9190-012177145e10': 'Global Administrator',
    'e8611ab8-c189-46e8-94e1-60213ab1f814': 'Privileged Role Administrator',
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': 'Privileged Authentication Administrator',
    '29232cdf-9323-42fd-ade2-1d097af3e4de': 'Exchange Administrator',
    '31392ffb-586c-42d1-9346-e59415a2cc4e': 'Exchange Recipient Administrator',
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': 'SharePoint Administrator',
    'fe930be7-5e62-47db-91af-98c3a49a38b1': 'User Administrator',
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': 'Application Administrator',
    '158c047a-c907-4556-b7ef-446551a6b5f7': 'Cloud Application Administrator',
    '194ae4cb-b126-40b2-bd5b-6091b380977d': 'Security Administrator',
    '5d6b6bb7-de71-4623-b4af-96380a352509': 'Security Reader',
    '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f': 'Security Operator',
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9': 'Conditional Access Administrator',
    'f2ef992c-3afb-46b9-b7cf-a126ee74c451': 'Global Reader',
    '729827e3-9c14-49f7-bb1b-9608f156bbb8': 'Helpdesk Administrator',
    '966707d0-3269-4727-9be2-8c3a10f19b9d': 'Password Administrator',
    'c4e39bd9-1100-46d3-8c65-fb160da0071f': 'Authentication Administrator',
    'b0f54661-2d74-4c50-afa3-1ec803f12efe': 'Billing Administrator',
    '3a2c62db-5318-420d-8d74-23affee5d9d5': 'Intune Administrator',
    '69091246-20e8-4a56-aa4d-066075b2a7a8': 'Teams Administrator',
    '17315797-102d-40b4-93e0-432062caca18': 'Compliance Administrator',
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2': 'Hybrid Identity Administrator',
    'fdd7a751-b60b-444a-984c-02652fe8fa1c': 'Groups Administrator',
    'd29b2b05-8046-44ba-8758-1e26182fcf32': 'Directory Synchronization Accounts',
    '88d8e3e3-8f55-4a1e-953a-9b9898b8876b': 'Directory Readers',
    '4a5d8f65-41da-4de4-8968-e035b65339cf': 'Reports Reader',
    '95e79109-95c0-4d8e-aee3-d01accf2d47b': 'Guest Inviter',
    '7698a772-787b-4ac8-901f-60d6b08affd2': 'Cloud Device Administrator',
    '9f06204d-73c1-4d4c-880a-6edb90606fd8': 'Microsoft Entra Joined Device Local Administrator',
}


def name_list(items):
    """At most MAX_NAMED identifiers, then 'and N more'."""
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def label(principal, excluded_by=None):
    """'kind:id' plus what the payload already says about it: a built-in role's name and the blocking policies that
    exclude it. Nothing is looked up."""
    notes = []
    if principal.startswith('role:'):
        role = ROLE_NAMES.get(principal[5:].lower())
        if role:
            notes.append(role)
    names = (excluded_by or {}).get(principal) or []
    if names:
        shown = ", ".join(names[:2])
        if len(names) > 2:
            shown = shown + " and " + str(len(names) - 2) + " more"
        notes.append("excluded by " + shown)
    if notes:
        return principal + " (" + "; ".join(notes) + ")"
    return principal


def principals(users, fields):
    found = []
    for field, kind in fields:
        values = users.get(field) if isinstance(users, dict) else None
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, str) and value.strip():
                found.append(kind + ":" + value.strip()[:64])
    return found


def as_dict(value):
    return value if isinstance(value, dict) else {}


def unread_body(body):
    """True when a Graph body is an error, a refusal or a workflow step error rather than data."""
    return (not isinstance(body, dict) or "error" in body or "vendorErrorAsResponse" in body
            or body.get("stepError") is True)


def security_defaults_enabled(data):
    """True only when the merged Security Defaults read shows isEnabled true; anything else is no evidence."""
    defaults = data.get("securityDefaults") if isinstance(data, dict) else None
    if unread_body(defaults):
        return False
    enabled = defaults.get("isEnabled")
    if isinstance(enabled, str) and enabled.strip().lower() in ("true", "false"):
        enabled = enabled.strip().lower() == "true"
    return enabled is True


def policy_list(data):
    """(policies, partial, reason). policies is None with a reason when the list was not read."""
    if not isinstance(data, dict):
        return None, False, "the Conditional Access policy list was not read (no response body)"
    body = data.get("conditionalAccessPolicies") if "conditionalAccessPolicies" in data else data
    if unread_body(body):
        return None, False, "the Conditional Access policy list was not read (Microsoft Graph returned an error or refused the read)"
    policies = body.get("value")
    if not isinstance(policies, list):
        return None, False, "the Conditional Access policy list was not read (no policy list in the response)"
    for p in policies:
        if not isinstance(p, dict):
            return None, False, "the Conditional Access policy list was not read whole (an entry is not a policy)"
    next_link = body.get("@odata.nextLink")
    partial = body.get("paginationTruncated") is True or (
        isinstance(next_link, str) and next_link.strip() not in ("", "None", "null"))
    return policies, partial, ""


def evaluate(data):
    """Core evaluation logic."""
    try:
        policies = data.get('value', [])
        legacy_block = [
            p for p in policies
            if p.get('state') == 'enabled'
            and any(
                client_type in p.get('conditions', {}).get('clientAppTypes', [])
                for client_type in LEGACY_CLIENTS
            )
            and p.get('grantControls', {}).get('builtInControls') == ['block']
        ]
        result = {
            "legacyAuthBlocked": len(legacy_block) > 0,
            "blockingPolicies": len(legacy_block)
        }
        if legacy_block:
            # Coverage per principal: a principal is blocked when at least one blocking policy includes it
            # (directly or through All users) and that same policy does not exclude it. Every principal named
            # in any blocking policy is checked, so an account excluded from the All-users block and not
            # included by a scoped one is named, even when another policy does not exclude it.
            all_users = False
            scoped = []
            rules = []
            candidates = []
            excluded_by = {}
            for p in legacy_block:
                users = p.get('conditions', {}).get('users', {})
                excluded = set(principals(users, EXCLUDE_FIELDS))
                policy_name = str(p.get('displayName') or p.get('id') or 'an unnamed policy').strip()[:MAX_POLICY_NAME]
                for x in sorted(excluded):
                    if x not in excluded_by:
                        excluded_by[x] = []
                    if policy_name not in excluded_by[x]:
                        excluded_by[x].append(policy_name)
                included = principals(users, INCLUDE_FIELDS)
                includes_all = "user:All" in included
                if includes_all:
                    all_users = True
                rules.append((includes_all, set(included), excluded))
                for x in included:
                    if x not in scoped:
                        scoped.append(x)
                for x in list(excluded) + included:
                    if x not in SPECIAL_PRINCIPALS and x not in candidates:
                        candidates.append(x)
            exempt = sorted(
                x for x in candidates
                if not any((includes_all or x in included) and x not in excluded
                           for includes_all, included, excluded in rules)
            )
            result["exemptPrincipals"] = len(exempt)
            result["exemptPrincipalIds"] = exempt
            result["exemptPrincipalLabels"] = [label(x, excluded_by) for x in exempt]
            if not all_users:
                result["blockScope"] = sorted(scoped)
                result["blockScopeLabels"] = [label(x) for x in sorted(scoped)]
        return result
    except Exception as e:
        return {"legacyAuthBlocked": False, "error": str(e)}


def transform(input):
    criteriaKey = "legacyAuthBlocked"
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
                api_errors=["Input validation failed: the Conditional Access policy list was not read"]
            )

        if security_defaults_enabled(data):
            return create_response(
                result={criteriaKey: True, "securityDefaultsEnabled": True},
                validation=validation,
                pass_reasons=[f"{criteriaKey} check passed: Security Defaults are enabled, so Microsoft Entra ID blocks "
                              "legacy authentication protocols (POP, IMAP, SMTP AUTH, Exchange ActiveSync) for every "
                              "account"],
                input_summary={criteriaKey: True, "securityDefaultsEnabled": True}
            )

        policies, partial, unread = policy_list(data)
        if policies is None:
            return create_response(result={criteriaKey: None}, validation=validation, api_errors=[unread])
        if not policies:
            return create_response(
                result={criteriaKey: None, "blockingPolicies": 0},
                validation=validation,
                api_errors=["Microsoft Graph returned no Conditional Access policies. Legacy authentication may still "
                            "be blocked by Security Defaults (not read, or read as off) or by Exchange Online "
                            "authentication policies (not read), so an empty list is not evidence either way"]
            )

        eval_result = evaluate({"value": policies})
        if "error" in eval_result:
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=["The Conditional Access policy list could not be evaluated: " + str(eval_result["error"])[:200]]
            )
        if partial and not eval_result.get(criteriaKey):
            return create_response(
                result={criteriaKey: None, "blockingPolicies": 0},
                validation=validation,
                api_errors=["The Conditional Access policy list is partial (a next page was not read) and no policy "
                            "on the pages read blocks legacy clients, so a blocking policy may be on a page not read"]
            )
        result_value = eval_result.get(criteriaKey, False)
        exempt = eval_result.get("exemptPrincipalIds") or []
        exempt_labels = eval_result.get("exemptPrincipalLabels") or exempt
        scope = eval_result.get("blockScope")
        scope_labels = eval_result.get("blockScopeLabels") or scope
        extra_fields = {k: v for k, v in eval_result.items()
                        if k not in [criteriaKey, "error", "exemptPrincipalIds", "blockScope",
                                     "exemptPrincipalLabels", "blockScopeLabels"]}
        summary = {criteriaKey: result_value, **extra_fields}
        if exempt:
            summary["exemptPrincipalIds"] = exempt[:MAX_NAMED]
        if scope is not None:
            summary["blockScope"] = scope[:MAX_NAMED]

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            reason = (f"{criteriaKey} check passed: {extra_fields.get('blockingPolicies', 0)} enabled Conditional "
                      "Access policy(ies) block legacy clients (POP, IMAP, SMTP AUTH, Exchange ActiveSync)")
            if exempt:
                reason = (reason + "; " + str(len(exempt)) + " account(s), group(s) or role(s) not covered by any "
                          "blocking policy can still use them: " + name_list(exempt_labels))
            if scope is not None:
                reason = (reason + "; no blocking policy targets all users, the block reaches only: "
                          + (name_list(scope_labels) if scope else "no one named"))
            pass_reasons.append(reason)
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
            if exempt or scope is not None:
                recommendations.append("Review the accounts named above: remove each exclusion that is not a "
                                       "documented break-glass account, and target the block at All users")
        else:
            if "error" in eval_result:
                fail_reasons.append(f"{criteriaKey} check failed")
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append(f"{criteriaKey} check failed: no enabled Conditional Access policy blocks "
                                    "legacy clients (POP, IMAP, SMTP AUTH, Exchange ActiveSync), so every account "
                                    "in the tenant can use them")
            recommendations.append(f"Review Microsoft Entra ID configuration for {criteriaKey}")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            api_errors=[f"Transformation error: {str(e)}"]
        )
