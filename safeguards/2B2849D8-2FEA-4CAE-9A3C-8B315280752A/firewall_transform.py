"""
Transformation: firewall_transform
Vendor: Cloudflare (API v4)  |  Category: Network Security / Firewall
Answers: isFirewallEnabled
Source: getFirewallRules, GET https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules. Integration-Service
returns the Cloudflare body under apiResponse (returnSpec rawResponse) beside "rules" (returnSpec result, which
defaults to [] when the call fails). Cloudflare body: {"success", "errors", "messages", "result": [...],
"result_info": {"count", "page", "per_page", "total_count"}}.

The Firewall Rules API is deprecated (Cloudflare API deprecations, 2025-06-15) in favour of WAF custom rules on the
Rulesets API, GET /zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint, whose body carries
"result": {"phase", "rules": [...]}. Both shapes are read so the definition can move to the Rulesets API without a
window in which this check breaks.

Fields read, per the Cloudflare API reference:
    Firewall Rules  paused (bool), filter.paused (bool), action: block | challenge | js_challenge |
                    managed_challenge | allow | log | bypass
    Rulesets        enabled (bool, "whether the rule should be executed"), action

isFirewallEnabled: at least one custom firewall rule is active (not paused, not disabled) with an enforcing action
(block, challenge, js_challenge, managed_challenge). Rules present with none active and enforcing -- every rule
paused, or only allow, log, bypass or skip -- is False.
paused and enabled are booleans, and a stored replay can carry them as text: "true" and "false" (any case, any spacing)
read as the booleans, and null, an empty string and "None"/"null" read as absent (not paused, enabled). Any other
value (a number, "maybe", a list) cannot be read. A rule that could enforce and carries a flag that cannot be read is
not counted as active; when no other rule is active and enforcing the answer is None, never False.
Scope: the zone's custom firewall rules only. Managed rulesets (http_request_firewall_managed) are a separate phase and
are not read, so the reason names the scope.

Not evaluated (None with a dataCollection error): an empty, error or unrecognised body; success false; no rules at
all, because the deprecated endpoint and a zone that relies on managed rules alone both read as an empty list; a
partial page that shows no active enforcing rule; or a rule that could enforce whose paused or enabled flag cannot be
read, with no other rule active and enforcing. A page is partial when result_info says more rules exist (total_count
above the rules read, total_pages above one unless total_count equals the rules read, a page that does not start at
the beginning, a cursor still set), when result_info or the paging block is present but is not an object, or when a
paging block carries pages above one or a next link. An active enforcing rule
that was read still proves True on a partial page.

isFirewallLoggingEnabled is not answered here. Neither API carries a field that evidences firewall event logging
(the Rulesets logging object configures skip rules only), so that criterion is document-only; see the C1a validation
record for the definition change. Previously this file read isFirewallEnabled and isFirewallLoggingEnabled as fields
of the Cloudflare body, which sends neither, so both were False for every zone.
"""
import json
from datetime import datetime, timezone

KEY = "isFirewallEnabled"

WRAPPERS = ("apiResponse", "api_response", "rawResponse", "response", "Output")

ENFORCING_ACTIONS = ("block", "challenge", "js_challenge", "managed_challenge")

MAX_NAMED = 20


def to_obj(raw):
    """A parsed JSON value, or None for an empty or unparseable body."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        text = raw.strip()
        if text == "":
            return None
        try:
            return json.loads(text)
        except Exception:
            return None
    return raw


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None):
    """Standardized transformation response. dataCollection is derived from the values: a key left None was not
    measured, so the status is "error" and Token-Service records Not evaluated rather than Failed."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    unmeasured = [k for k in result if result[k] is None]
    api_errors = []
    if unmeasured:
        api_errors = (fail_reasons or [])[:1] or ["not measured: " + ", ".join(unmeasured)]
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_errors else "success", "errors": api_errors},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transformation_errors else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                "schemaVersion": "2.0",
                "transformationId": "firewall_transform",
                "vendor": "Cloudflare",
                "category": "Network Security",
            },
        },
    }


def not_measured(validation, reason, summary=None, transformation_errors=None):
    """None: reads Not evaluated, never True or False."""
    return create_response({KEY: None}, validation, fail_reasons=[reason], input_summary=summary,
                           transformation_errors=transformation_errors)


def as_int(value):
    """A whole number from an int or a digit string, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def page_int(value):
    """A whole-number page field, or None. Stored replays stringify numbers: 4, 4.0, "4" and "4.0" are all 4."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        number = float(str(value).strip())
        if number != number or number in (float("inf"), float("-inf")):
            return None
        whole = int(number)
        if whole != number:
            return None
        return whole
    except Exception:
        return None


def page_field_unreadable(value):
    """True when a page field is present but is not a whole number (null, an empty string and the stringified nulls are absent)."""
    if value is None:
        return False
    if isinstance(value, str) and value.strip().lower() in ("", "none", "null"):
        return False
    return page_int(value) is None


def page_cursor(value):
    """A pagination cursor, or None. Stored replays stringify null as "None" or "null"."""
    if value is None or value is False:
        return None
    text = str(value).strip()
    if text.lower() in ("", "none", "null", "false"):
        return None
    return text


def marker_set(value):
    """True when a next-page marker (a cursor, a link or a list of links) is set."""
    if isinstance(value, (list, dict)):
        return len(value) > 0
    return page_cursor(value) is not None


def flag_kind(value):
    """"true" or "false" for a boolean or its text, "absent" for null, an empty string and the stringified nulls, else
    "unknown" (a number, a list, any other text)."""
    if value is None:
        return "absent"
    if isinstance(value, bool):
        if value:
            return "true"
        return "false"
    if isinstance(value, str):
        text = value.strip().lower()
        if text == "true":
            return "true"
        if text == "false":
            return "false"
        if text in ("", "none", "null"):
            return "absent"
    return "unknown"


def rule_state(rule):
    """"inactive" when the rule is paused or disabled, "unreadable" when a flag it carries cannot be read and nothing
    else shows it inactive, else "active". An absent flag is the default: not paused, enabled."""
    flt = rule.get("filter")
    paused = [flag_kind(rule.get("paused"))]
    if isinstance(flt, dict):
        paused.append(flag_kind(flt.get("paused")))
    enabled = flag_kind(rule.get("enabled"))
    if "true" in paused or enabled == "false":
        return "inactive"
    if "unknown" in paused or enabled == "unknown":
        return "unreadable"
    return "active"


def more_rules_exist(body, rules_read):
    """True when the body shows rules beyond the ones it carries (a partial page)."""
    info = body.get("result_info")
    if not isinstance(info, dict):
        if page_cursor(info) is not None:
            return True  # present but not an object (text, a number, a list): it cannot be read, so it is partial
        info = {}
    paging = body.get("paging")
    if paging is not None and not isinstance(paging, dict):
        if page_cursor(paging) is not None:
            return True
        paging = {}
    if paging is None:
        paging = {}
    total_raw = info.get("total_count")
    if page_field_unreadable(total_raw):
        return True
    total = page_int(total_raw)
    if total is not None and total > rules_read:
        return True
    for pages_raw in (info.get("total_pages"), paging.get("pages")):
        if page_field_unreadable(pages_raw):
            return True
        pages = page_int(pages_raw)
        if pages is not None and pages > 1 and total != rules_read:
            return True
    page_raw = info.get("page")
    if page_field_unreadable(page_raw):
        return True
    page = page_int(page_raw)
    if page is not None and page > 1:
        return True
    cursors = info.get("cursors")
    if isinstance(cursors, dict):
        if marker_set(cursors.get("after")):
            return True
    elif marker_set(cursors):
        return True
    if marker_set(info.get("cursor")) or marker_set(paging.get("next")):
        return True
    return False


def envelope_error(obj):
    """A short reason when obj is an error envelope rather than a Cloudflare body, else None."""
    if not isinstance(obj, dict):
        return None
    if obj.get("success") is False:
        errors = obj.get("errors")
        first = errors[0] if isinstance(errors, list) and errors else errors
        if isinstance(first, dict):
            first = str(first.get("code") or "") + " " + str(first.get("message") or "")
        return "Cloudflare answered success false: " + (str(first).strip()[:200] or "no error given")
    err = obj.get("error")
    if err is True or isinstance(err, (str, dict)):
        detail = obj.get("message") or err
        if isinstance(detail, dict):
            detail = detail.get("message") or json.dumps(detail)[:200]
        return "the call did not return data: " + str(detail)[:300]
    for name in ("statusCode", "status_code"):
        code = as_int(obj.get(name))
        if code is not None and code >= 400:
            return "the call returned HTTP " + str(code)
    vendor = obj.get("vendorErrorAsResponse")
    if isinstance(vendor, dict):
        return "the call returned " + str(vendor.get("status") or "an error") + ": " + str(vendor.get("message"))[:200]
    return None


def cloudflare_body(raw):
    """(body, None) for a Cloudflare v4 body carrying a result, else (None, reason)."""
    cur = to_obj(raw)
    outer = None
    for depth in range(6):
        if cur is None:
            return None, "the response body is empty; nothing was read from Cloudflare"
        if not isinstance(cur, dict):
            return None, "the response is not a JSON object"
        why = envelope_error(cur)
        if why:
            return None, why
        if "result" in cur and ("success" in cur or "result_info" in cur or "errors" in cur):
            return cur, None
        if outer is None and isinstance(cur.get("rules"), list):
            outer = cur
        nxt = None
        for w in WRAPPERS:
            if isinstance(cur.get(w), (dict, str)):
                nxt = to_obj(cur.get(w))
                break
        if nxt is None:
            break
        cur = nxt
    # No raw body: a non-empty returnSpec "rules" list is real data (it defaults to [] only on failure).
    if outer is not None and len(outer.get("rules")) > 0:
        return {"result": outer.get("rules")}, None
    return None, "the response carries no Cloudflare result (not the firewall rules or custom rules body)"


def rule_label(rule):
    text = rule.get("description") or rule.get("ref") or rule.get("id") or "?"
    return "'" + str(text)[:60] + "'"


def name_list(items):
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def transform(input):
    validation = {"status": "unknown", "errors": [], "warnings": []}
    try:
        if isinstance(input, dict) and "validation" in input and "data" in input:
            if isinstance(input.get("validation"), dict):
                validation = input.get("validation")
            raw = input.get("data")
        else:
            raw = input

        if validation.get("status") == "failed":
            return not_measured(validation, "Input validation failed: nothing was measured.")

        body, why = cloudflare_body(raw)
        if why:
            return not_measured(validation, "Cloudflare firewall rules read: " + why + ".")

        result = body.get("result")
        if isinstance(result, dict) and isinstance(result.get("rules"), list):
            source = "WAF custom rules (" + str(result.get("phase") or "entry point ruleset") + ")"
            rules = result.get("rules")
        elif isinstance(result, list):
            source = "Firewall Rules API"
            rules = result
        elif isinstance(result, dict) and "phase" in result:
            source = "WAF custom rules (" + str(result.get("phase")) + ")"
            rules = []
        else:
            return not_measured(validation, "Cloudflare firewall rules read: the result is neither a rule list nor a "
                                "ruleset.")

        for rule in rules:
            if not isinstance(rule, dict):
                return not_measured(validation, "Cloudflare firewall rules read: the rules are not a list of objects.")

        if len(rules) == 0:
            return not_measured(validation, "Cloudflare (" + source + ") returned no custom firewall rule. An empty "
                                "list is what the deprecated Firewall Rules API and a zone relying on managed rules "
                                "alone both return, so it shows nothing either way.",
                                {"source": source, "rulesRead": 0})

        partial = more_rules_exist(body, len(rules))

        enforcing = []
        inactive = []
        non_enforcing = []
        unreadable = []
        unreadable_rules = 0
        for rule in rules:
            state = rule_state(rule)
            if state == "inactive":
                inactive.append(rule_label(rule))
                continue
            action = str(rule.get("action") or "").strip().lower()
            if state == "unreadable":
                unreadable_rules = unreadable_rules + 1
                if action in ENFORCING_ACTIONS:
                    unreadable.append(rule_label(rule) + " (" + action + ")")
                else:
                    non_enforcing.append(rule_label(rule) + " (" + (action or "no action") + ")")
                continue
            if action in ENFORCING_ACTIONS:
                enforcing.append(rule_label(rule) + " (" + action + ")")
            else:
                non_enforcing.append(rule_label(rule) + " (" + (action or "no action") + ")")

        summary = {"source": source, "rulesRead": len(rules), "activeEnforcingRules": len(enforcing),
                   "pausedOrDisabledRules": len(inactive), "activeNonEnforcingRules": len(non_enforcing),
                   "rulesWithUnreadableFlags": unreadable_rules, "partialRead": partial}
        scope = " Scope: custom firewall rules only; managed rulesets are not read."

        if enforcing:
            return create_response(
                {KEY: True}, validation,
                pass_reasons=["Cloudflare (" + source + "): " + str(len(enforcing)) + " of " + str(len(rules)) +
                              " custom firewall rules are active and enforce: " + name_list(enforcing) + "." + scope],
                input_summary=summary)
        if partial:
            return not_measured(validation, "Cloudflare (" + source + "): the first page of " + str(len(rules)) +
                                " rules has no active enforcing rule, and more rules exist than were read.", summary)
        if unreadable:
            return not_measured(validation, "Cloudflare (" + source + "): " + str(len(unreadable)) + " rule(s) that "
                                "could enforce carry a paused or enabled flag that cannot be read, and no other rule "
                                "is active and enforcing: " + name_list(unreadable) + ".", summary)
        return create_response(
            {KEY: False}, validation,
            fail_reasons=["Cloudflare (" + source + "): none of " + str(len(rules)) + " custom firewall rules is "
                          "active and enforcing. Paused or disabled: " + (name_list(inactive) or "none") +
                          "; active but allow, log, bypass or skip only: " + (name_list(non_enforcing) or "none") +
                          "." + scope],
            recommendations=["Enable at least one custom rule with a block or challenge action, or confirm the "
                             "zone's protection comes from managed rulesets."],
            input_summary=summary)

    except Exception as e:
        message = "Transformation error: " + str(e)[:300]
        return not_measured(validation, message, transformation_errors=[message])
