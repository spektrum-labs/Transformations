"""
Transformation: isURLRewriteEnabled
Vendor: Google Workspace
Category: Email Security

Evaluates whether Gmail checks links before delivery.

Google Workspace has no literal "URL rewrite" the way a mail gateway does. The
equivalent control is the Gmail "Links and external images" safety policy, which
scans links behind shorteners and warns on untrusted links. It is exposed by the
Cloud Identity Policy API as settings/gmail.links_and_external_images.

Previously this transform read a top-level "urlRewrite" field from the mail-server
DNS tool, which never returns one, so the criterion was false for every customer.
"""

import json
from datetime import datetime

SETTING_TYPE = "gmail.links_and_external_images"

# Fields that constitute "URLs are checked before delivery". External image
# scanning is deliberately excluded: it governs images, not links.
REQUIRED_FIELDS = ["enableShortenerScanning", "enableAggressiveWarningsOnUntrustedLinks"]


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
                "transformationId": "isURLRewriteEnabled",
                "vendor": "Google Workspace",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isURLRewriteEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        policies = []
        if isinstance(data, dict):
            policies = data.get("policies", [])
        elif isinstance(data, list):
            # Token-Service can hand list-shaped API data straight through
            policies = data

        # Collect every link-protection policy. Google returns one per org unit,
        # so the tenant is only covered if all of them have link checking on.
        link_policies = []
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            setting = policy.get("setting", {})
            if not isinstance(setting, dict):
                continue
            if str(setting.get("type", "")).endswith(SETTING_TYPE):
                value = setting.get("value", {})
                link_policies.append({
                    "orgUnit": policy.get("policyQuery", {}).get("orgUnit", "unknown"),
                    "value": value if isinstance(value, dict) else {}
                })

        enabled_count = 0
        disabled_fields = []

        for entry in link_policies:
            value = entry["value"]
            entry_enabled = True
            for field in REQUIRED_FIELDS:
                if not bool(value.get(field, False)):
                    entry_enabled = False
                    if field not in disabled_fields:
                        disabled_fields.append(field)
            if entry_enabled:
                enabled_count += 1
            additional_findings.append({
                "metric": entry["orgUnit"],
                "value": entry_enabled,
                "reason": "Link checking enabled" if entry_enabled else "Link checking not fully enabled"
            })

        is_url_rewrite_enabled = len(link_policies) > 0 and enabled_count == len(link_policies)

        if is_url_rewrite_enabled:
            pass_reasons.append(
                "Gmail link protection enabled across all %d org unit policies" % len(link_policies)
            )
        elif len(link_policies) == 0:
            fail_reasons.append(
                "No %s policy returned; cannot confirm links are checked before delivery" % SETTING_TYPE
            )
            recommendations.append(
                "Verify the Cloud Identity Policy API returns Gmail safety policies for this tenant"
            )
        else:
            fail_reasons.append(
                "Link checking not enabled on %d of %d org unit policies (missing: %s)"
                % (len(link_policies) - enabled_count, len(link_policies), ", ".join(disabled_fields))
            )
            recommendations.append(
                "In Admin console > Apps > Google Workspace > Gmail > Safety > Links and external "
                "images, enable shortener scanning and aggressive warnings on untrusted links"
            )

        return create_response(
            result={
                criteriaKey: is_url_rewrite_enabled,
                "linkPolicyCount": len(link_policies),
                "enabledPolicyCount": enabled_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalPolicies": len(policies),
                "linkPolicies": len(link_policies),
                "enabledPolicies": enabled_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
