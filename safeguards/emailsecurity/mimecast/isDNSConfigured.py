"""
Transformation: isDNSConfigured
Criterion: DNS Configuration (DMARC, DKIM, SPF)
Vendor: Mimecast
Method: getInternalDomain

Evaluates whether DMARC, DKIM, and SPF records are set up properly for all
internal domains registered in Mimecast. The getInternalDomain endpoint returns
each domain along with a 'dns' nested object that surfaces per-record verification
states. A domain is considered fully configured when all three record types
(DKIM, DMARC, SPF) are present and verified. The overall criterion passes only
when every domain that has DNS data returned is fully configured.
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


def check_dns_record(dns_obj, record_type):
    """
    Check if a specific DNS record type is configured/valid within a dns object.
    Handles various possible field shapes from Mimecast.
    Returns True if the record appears configured, False otherwise.
    """
    if not isinstance(dns_obj, dict):
        return False
    record_lower = record_type.lower()
    for key in dns_obj:
        if key.lower() == record_lower:
            val = dns_obj[key]
            if isinstance(val, dict):
                valid = val.get("valid") or val.get("verified") or val.get("status") or val.get("configured")
                if valid is True:
                    return True
                if isinstance(valid, str):
                    return valid.lower() in ("verified", "valid", "ok", "pass", "configured", "true")
                return False
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                return val.lower() in ("verified", "valid", "ok", "pass", "configured", "true")
    return False


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    items = data.get("data") or []
    fail_field = data.get("fail") or []

    # API-level errors
    api_errors = []
    if fail_field:
        for f in fail_field:
            if isinstance(f, dict):
                msg = f.get("message") or f.get("msg") or str(f)
                api_errors.append(msg)
            else:
                api_errors.append(str(f))

    if not items:
        return create_response(
            result={
                "isDNSConfigured": False,
                "totalDomains": 0,
                "domainsWithDnsData": 0,
                "domainsWithDkim": 0,
                "domainsWithDmarc": 0,
                "domainsWithSpf": 0,
                "domainsFullyConfigured": 0,
            },
            validation=validation,
            fail_reasons=["No internal domains were returned by the Mimecast API. Cannot verify DMARC, DKIM, or SPF configuration."],
            recommendations=["Register at least one internal domain in Mimecast and configure DKIM, DMARC, and SPF DNS records for it."],
            input_summary={"totalDomains": 0, "apiErrors": api_errors},
            api_errors=api_errors,
            metadata={
                "transformationId": "isDNSConfigured",
                "vendor": "Mimecast",
                "category": "emailsecurity",
            }
        )

    total_domains = 0
    domains_with_dns_data = 0
    domains_with_dkim = 0
    domains_with_dmarc = 0
    domains_with_spf = 0
    domains_fully_configured = 0
    domain_names = []
    missing_dns_domains = []
    missing_record_details = []

    for item in items:
        if not isinstance(item, dict):
            continue
        # Skip truncation markers (e.g. {"_truncated": "+92 more items"})
        if "_truncated" in item and len(item) == 1:
            continue
        domain_name = item.get("domain") or ""
        total_domains = total_domains + 1
        if domain_name:
            domain_names.append(domain_name)

        dns_obj = item.get("dns")
        if not dns_obj or not isinstance(dns_obj, dict):
            missing_dns_domains.append(domain_name)
            continue

        domains_with_dns_data = domains_with_dns_data + 1

        has_dkim = check_dns_record(dns_obj, "dkim")
        has_dmarc = check_dns_record(dns_obj, "dmarc")
        has_spf = check_dns_record(dns_obj, "spf")

        if has_dkim:
            domains_with_dkim = domains_with_dkim + 1
        if has_dmarc:
            domains_with_dmarc = domains_with_dmarc + 1
        if has_spf:
            domains_with_spf = domains_with_spf + 1

        if has_dkim and has_dmarc and has_spf:
            domains_fully_configured = domains_fully_configured + 1
        else:
            missing_records = []
            if not has_dkim:
                missing_records.append("DKIM")
            if not has_dmarc:
                missing_records.append("DMARC")
            if not has_spf:
                missing_records.append("SPF")
            if missing_records:
                missing_record_details.append(
                    f"{domain_name}: missing " + ", ".join(missing_records)
                )

    # Determine overall pass/fail
    if domains_with_dns_data == 0:
        # Domains exist but no DNS verification data in any response item
        is_configured = False
        pass_reasons = []
        sample = ", ".join(domain_names[:5]) + ("..." if len(domain_names) > 5 else "")
        fail_reasons = [
            f"DNS verification data (DKIM, DMARC, SPF) was not found in the response for any of the {total_domains} internal domain(s) registered in Mimecast. "
            "The 'dns' field was absent on all returned domain records, indicating DNS records may not be configured or verified in Mimecast. "
            f"Sample domains checked: {sample}"
        ]
        recommendations = [
            "Configure DKIM, DMARC, and SPF DNS records for all internal domains in Mimecast. "
            "Verify DNS configuration under Administration > Gateway > Policies or the Domain configuration section."
        ]
    elif domains_fully_configured == domains_with_dns_data and domains_fully_configured > 0:
        is_configured = True
        pass_reasons = [
            f"All {domains_fully_configured} domain(s) with DNS verification data have DKIM, DMARC, and SPF records properly configured "
            f"({domains_with_dkim} DKIM, {domains_with_dmarc} DMARC, {domains_with_spf} SPF verified out of {domains_with_dns_data} domains with DNS data)."
        ]
        fail_reasons = []
        recommendations = []
        if missing_dns_domains:
            pass_reasons.append(
                f"Note: {len(missing_dns_domains)} domain(s) did not include DNS verification data in this response and were not evaluated."
            )
    else:
        is_configured = False
        pass_reasons = []
        fail_reasons_list = []
        if missing_record_details:
            detail_sample = "; ".join(missing_record_details[:5]) + ("..." if len(missing_record_details) > 5 else "")
            fail_reasons_list.append(
                f"{len(missing_record_details)} domain(s) are missing one or more required DNS records: {detail_sample}"
            )
        if missing_dns_domains:
            domain_sample = ", ".join(missing_dns_domains[:5]) + ("..." if len(missing_dns_domains) > 5 else "")
            fail_reasons_list.append(
                f"{len(missing_dns_domains)} domain(s) returned no DNS verification data: {domain_sample}"
            )
        fail_reasons = fail_reasons_list
        recommendations = [
            "Ensure DKIM, DMARC, and SPF DNS records are published and verified for all internal domains in Mimecast. "
            "Review each domain listed under Administration > Gateway > Policies to confirm record configuration."
        ]

    return create_response(
        result={
            "isDNSConfigured": is_configured,
            "totalDomains": total_domains,
            "domainsWithDnsData": domains_with_dns_data,
            "domainsWithDkim": domains_with_dkim,
            "domainsWithDmarc": domains_with_dmarc,
            "domainsWithSpf": domains_with_spf,
            "domainsFullyConfigured": domains_fully_configured,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalDomains": total_domains,
            "domainsWithDnsData": domains_with_dns_data,
            "domainsFullyConfigured": domains_fully_configured,
        },
        api_errors=api_errors,
        metadata={
            "transformationId": "isDNSConfigured",
            "vendor": "Mimecast",
            "category": "emailsecurity",
        }
    )
