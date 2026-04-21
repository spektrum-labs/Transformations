"""
Transformation: isBackupEncrypted
Vendor: Rubrik  |  Category: nydfs / Backups
Evaluates: Whether backup data is encrypted at rest via archival configurations in SLA Domains.
Checks that at least one SLA domain has archivalSpecs with a storageSetting.groupType value,
indicating encrypted archival targets are configured and backup data at rest is protected.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEncrypted", "vendor": "Rubrik", "category": "nydfs/Backups"}
        }
    }


def domain_has_encrypted_archival(domain):
    archival_specs = domain.get("archivalSpecs", None)
    if not archival_specs or not isinstance(archival_specs, list):
        return False
    for spec in archival_specs:
        storage_setting = spec.get("storageSetting", None)
        if storage_setting is None:
            continue
        group_type = storage_setting.get("groupType", None)
        if group_type is not None and group_type != "":
            return True
    return False


def evaluate(data):
    try:
        sla_domains = data.get("data", [])
        if not isinstance(sla_domains, list):
            sla_domains = []

        total_domains = len(sla_domains)
        domains_with_archival = 0
        encrypted_domains = []
        unencrypted_domains = []

        for domain in sla_domains:
            archival_specs = domain.get("archivalSpecs", None)
            if archival_specs and isinstance(archival_specs, list) and len(archival_specs) > 0:
                domains_with_archival = domains_with_archival + 1
                if domain_has_encrypted_archival(domain):
                    encrypted_domains.append(domain.get("name", "unnamed"))
                else:
                    unencrypted_domains.append(domain.get("name", "unnamed"))

        encrypted_count = len(encrypted_domains)
        result = encrypted_count > 0

        return {
            "isBackupEncrypted": result,
            "totalSlaDomains": total_domains,
            "domainsWithArchival": domains_with_archival,
            "encryptedArchivalCount": encrypted_count,
            "encryptedDomainNames": encrypted_domains,
            "unencryptedDomainNames": unencrypted_domains
        }
    except Exception as e:
        return {"isBackupEncrypted": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupEncrypted"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = eval_result.get("totalSlaDomains", 0)
        with_archival = eval_result.get("domainsWithArchival", 0)
        encrypted_count = eval_result.get("encryptedArchivalCount", 0)
        encrypted_names = eval_result.get("encryptedDomainNames", [])
        unencrypted_names = eval_result.get("unencryptedDomainNames", [])

        additional_findings.append("Total SLA domains: " + str(total))
        additional_findings.append("Domains with archival specs: " + str(with_archival))
        additional_findings.append("Domains with encrypted archival targets (groupType set): " + str(encrypted_count))

        if unencrypted_names:
            additional_findings.append("Domains with archival but no groupType detected: " + ", ".join(unencrypted_names))

        if result_value:
            pass_reasons.append("At least one SLA domain has an archival spec with a storageSetting.groupType indicating an encrypted archival target.")
            pass_reasons.append("Encrypted archival SLA domains: " + ", ".join(encrypted_names))
        else:
            if total == 0:
                fail_reasons.append("No SLA domains were returned by the Rubrik API.")
            elif with_archival == 0:
                fail_reasons.append("No SLA domains have archival specifications configured.")
                fail_reasons.append("Archival to an encrypted storage target is required for backup encryption compliance.")
            else:
                fail_reasons.append("SLA domains with archival specs exist but none have a storageSetting.groupType value indicating encryption.")
            recommendations.append("Configure archival specs on SLA domains to target encrypted storage locations.")
            recommendations.append("Ensure storageSetting.groupType is set on archival storage targets to indicate encryption compliance.")
            recommendations.append("Review Rubrik Security Cloud archival settings and add encrypted cloud or tape targets.")

        extra_fields = {
            "totalSlaDomains": total,
            "domainsWithArchival": with_archival,
            "encryptedArchivalCount": encrypted_count,
            "encryptedDomainNames": encrypted_names,
            "unencryptedDomainNames": unencrypted_names
        }

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalSlaDomains": total, "encryptedArchivalCount": encrypted_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
