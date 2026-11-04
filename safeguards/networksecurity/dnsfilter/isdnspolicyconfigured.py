"""
Transformation: isDNSPolicyConfigured
Vendor: DNSFilter
Category: Network Security / Policy Configuration

Passes when at least one live DNSFilter policy actually filters: it blocks one or more content
categories (`blacklist_categories`), or it is allow-list-only (`allow_list_only`).

Reads GET /v1/policies?organization_id=... (Integration-Service method getPolicies). The body is
JSON:API: {"data": [{"id": ..., "type": "policies", "attributes": {...}}], "links": {...}}.
Token-Service strips the `data` wrapper before calling transform, so the policy list usually
arrives as a bare list; a raw body keeps it under `data`. Policy fields sit under `attributes`.
The previous version read `blocked_categories` at the top level of each policy, a field the
API never returns, and then passed any organisation that had a policy at all.

A policy with `deleted_at` set is not counted. A body with no readable policy list, or a list
with no live policy, is not measured (None with a dataCollection error): every DNSFilter network
must point at a policy, so an empty list says the read did not see it, not that none exists.

Runs in Token-Service's RestrictedPython sandbox: no map(), no names starting with `_`.
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
                "transformationId": "isDNSPolicyConfigured",
                "vendor": "DNSFilter",
                "category": "Network Security"
            }
        }
    }


def policies_of(data):
    """The policy list: the body itself, or its `data` / `policies` list for a raw body. None when absent."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "policies"):
            if isinstance(data.get(key), list):
                return data[key]
    return None


def attributes_of(policy):
    """A policy's fields: under `attributes` (JSON:API), or the policy itself when already flattened."""
    if not isinstance(policy, dict):
        return None
    attributes = policy.get("attributes")
    return attributes if isinstance(attributes, dict) else policy


def why_unreadable(data):
    if not isinstance(data, (dict, list)):
        return "body is " + ("null" if data is None else "not an object or a list")
    if isinstance(data, dict):
        if not data:
            return "body is empty"
        for key in ("error", "errors", "message"):
            if key in data:
                return f"vendor {key}: {str(data[key])[:200]}"
        return "body is not a policy list (keys: " + ", ".join(sorted(str(k) for k in data)[:10]) + ")"
    return "the policy list is empty"


def transform(input):
    criteriaKey = "isDNSPolicyConfigured"
    validation = {"status": "unknown", "errors": [], "warnings": []}

    def not_measured(reason, input_summary=None, transformation_errors=None):
        return create_response(
            result={criteriaKey: None, "totalPolicies": None, "policiesWithBlocks": None,
                    "totalBlockedCategories": None},
            validation=validation,
            api_errors=[reason],
            fail_reasons=["DNSFilter policies could not be read"],
            recommendations=["Re-run the check; if it persists, confirm the DNSFilter API key can read the organisation's policies"],
            input_summary=input_summary,
            transformation_errors=transformation_errors
        )

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            errors = validation.get("errors", []) or ["schema rejected the body"]
            return not_measured("Input validation failed: " + "; ".join(str(e) for e in errors))

        policies = policies_of(data)
        if not policies:
            return not_measured(f"DNSFilter returned no readable policy list: {why_unreadable(data if policies is None else [])}")

        live = 0
        deleted = 0
        unreadable = 0
        with_blocks = 0
        allow_list_only = 0
        blocked_categories = 0
        best_name = None
        best_count = -1
        for policy in policies:
            attributes = attributes_of(policy)
            if attributes is None:
                unreadable += 1
                continue
            if attributes.get("deleted_at"):
                deleted += 1
                continue
            live += 1
            categories = attributes.get("blacklist_categories")
            allow_only = attributes.get("allow_list_only") is True
            if not isinstance(categories, list) and not allow_only:
                unreadable += 1
                continue
            count = len(categories) if isinstance(categories, list) else 0
            if allow_only:
                allow_list_only += 1
            if count > 0 or allow_only:
                with_blocks += 1
                blocked_categories += count
                if count > best_count:
                    best_count = count
                    best_name = attributes.get("name")

        summary = {"totalPolicies": live, "deletedPolicies": deleted, "unreadablePolicies": unreadable,
                   "policiesWithBlocks": with_blocks, "allowListOnlyPolicies": allow_list_only,
                   "totalBlockedCategories": blocked_categories}
        result = {criteriaKey: with_blocks > 0, "totalPolicies": live, "policiesWithBlocks": with_blocks,
                  "totalBlockedCategories": blocked_categories}

        if with_blocks > 0:
            reason = f"{with_blocks} of {live} live DNSFilter policies filter traffic"
            if best_count > 0:
                reason += f"; the strictest ({best_name or 'unnamed'}) blocks {best_count} content categories"
            if allow_list_only:
                reason += f"; {allow_list_only} allow-list-only"
            findings = [f"{unreadable} policy record(s) carry no readable category list and were not counted"] if unreadable else []
            return create_response(result=result, validation=validation, pass_reasons=[reason],
                                   additional_findings=findings, input_summary=summary)

        if live == 0 or unreadable:
            # A False needs every live policy read: one we could not read might be the one that filters.
            why = ("every policy returned is deleted" if live == 0 and not unreadable
                   else f"{unreadable} policy record(s) carry no readable category list")
            return not_measured(f"DNSFilter policies could not be measured: {why}", input_summary=summary)

        return create_response(
            result=result,
            validation=validation,
            fail_reasons=[f"None of the {live} live DNSFilter policies blocks a content category or is allow-list-only, so DNS filtering blocks nothing by category"],
            recommendations=["In DNSFilter, block at least the security categories (malware, phishing, botnet, cryptomining, newly seen domains) in the policy your networks and roaming clients use"],
            input_summary=summary
        )

    except Exception as e:
        validation = {"status": "error", "errors": [], "warnings": []}
        return not_measured(f"Transformation error: {str(e)}", transformation_errors=[str(e)])
