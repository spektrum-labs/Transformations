"""Transformation: isDNSConfigured — Mimecast getInternalDomain
Checks whether DNS (DMARC, DKIM, SPF / MX routing) is configured by
verifying that at least one internal domain has an active inbound type
registered with Mimecast, indicating DNS records point mail to Mimecast.
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    raw_items = data.get("data") or []
    fail_list = data.get("fail") or []

    # Filter out truncation markers (e.g. {"_truncated": "+112 more items"})
    domains = [
        item for item in raw_items
        if isinstance(item, dict) and "domain" in item
    ]

    total_domains = len(domains)

    # Active inbound domains: sendOnly=False and inboundType is set and non-empty
    inbound_domains = [
        d for d in domains
        if not d.get("sendOnly", True) and d.get("inboundType")
    ]
    inbound_count = len(inbound_domains)

    # Collect sample domain names for reporting (up to 5)
    sample_names = [d.get("domain", "") for d in inbound_domains[:5]]

    api_errors = []
    if fail_list:
        for f in fail_list:
            errs = f.get("errors") or []
            for e in errs:
                api_errors.append(e.get("message", "Unknown API error"))

    is_configured = inbound_count > 0

    inbound_types_seen = list({d.get("inboundType") for d in inbound_domains if d.get("inboundType")})

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_configured:
        pass_reasons.append(
            f"{inbound_count} of {total_domains} registered internal domains "
            f"have an active inbound DNS routing type configured in Mimecast "
            f"(inboundType values observed: {', '.join(inbound_types_seen)}). "
            f"Sample domains: {', '.join(sample_names)}. "
            "Active inbound routing confirms that MX records point to Mimecast and "
            "that DNS configuration (SPF, DKIM, DMARC) is in place for mail flow."
        )
    else:
        if total_domains == 0:
            fail_reasons.append(
                "No internal domains are registered with this Mimecast account. "
                "Without registered domains, DNS records (SPF, DKIM, DMARC) "
                "cannot be validated or enforced via Mimecast."
            )
            recommendations.append(
                "Register your organisation's email domains in the Mimecast administration "
                "console under Gateway > Domains, and ensure MX records, SPF, DKIM, and "
                "DMARC records are published in DNS."
            )
        else:
            fail_reasons.append(
                f"{total_domains} domain(s) are registered but none have an active "
                "inbound DNS routing type (all are send-only or have no inboundType). "
                "This indicates DNS/MX records may not be directing inbound mail through Mimecast."
            )
            recommendations.append(
                "Review domain configuration in Mimecast and ensure that MX records for "
                "each domain point to Mimecast, and that SPF, DKIM, and DMARC DNS records "
                "are published and verified."
            )

    return create_response(
        result={
            "isDNSConfigured": is_configured,
            "totalDomainsRegistered": total_domains,
            "inboundConfiguredDomains": inbound_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalDomainsRegistered": total_domains,
            "inboundConfiguredDomains": inbound_count,
            "inboundTypesObserved": inbound_types_seen,
        },
        api_errors=api_errors,
        metadata={
            "transformationId": "isDNSConfigured",
            "vendor": "Mimecast",
            "category": "Email Security",
        },
    )
