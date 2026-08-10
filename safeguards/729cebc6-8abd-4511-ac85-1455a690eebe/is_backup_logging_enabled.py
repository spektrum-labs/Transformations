"""
Transformation: isBackupLoggingEnabled
Vendor: Azure Recovery Services / Azure Data Protection
Category: Backup / Logging

Checks whether Azure backup diagnostic settings are configured with log
categories enabled and forwarding to a destination (Log Analytics workspace,
Storage Account, or Event Hub).

Data source: Azure Monitor diagnosticSettings ARM API (getVaultDiagnosticSettings),
iterated per vault from listVaults. Each entry is a { "value": [ ... ] } response.

Note: diagnostic settings are proxy resources and are NOT indexed by Azure Resource
Graph, so they cannot be read via an ARG join. The previous ARG-based query always
returned hasDiagnosticSettings=false regardless of configuration.
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
                "transformationId": "isBackupLoggingEnabled",
                "vendor": "Azure",
                "category": "Backup"
            }
        }
    }


def transform(input):
    criteriaKey = "isBackupLoggingEnabled"

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

        # Merged diagnosticSettings from iterating across all vaults, or a direct
        # { "value": [...] } response for a single vault.
        settings_data = data.get("diagnosticSettings", data)
        responses = []
        if isinstance(settings_data, list):
            for entry in settings_data:
                if isinstance(entry, dict):
                    responses.append(entry)
                elif isinstance(entry, list):
                    for sub in entry:
                        if isinstance(sub, dict):
                            responses.append(sub)
        elif isinstance(settings_data, dict):
            responses.append(settings_data)

        settings = []
        for resp in responses:
            value = resp.get("value", [])
            if isinstance(value, list):
                settings.extend([s for s in value if isinstance(s, dict)])
            elif isinstance(resp.get("properties"), dict):
                # A single diagnostic setting object rather than a list wrapper
                settings.append(resp)

        logging_enabled = False
        log_categories_found = []
        configured_settings = []
        incomplete_settings = []

        for setting in settings:
            props = setting.get("properties", {})
            if not isinstance(props, dict):
                continue

            enabled_categories = []
            for log in props.get("logs", []) or []:
                if not isinstance(log, dict) or not log.get("enabled"):
                    continue
                # Modern settings use categoryGroup ("allLogs"/"audit") and leave
                # category null; older ones name each category individually.
                label = log.get("category") or log.get("categoryGroup")
                if label:
                    enabled_categories.append(label)

            destinations = []
            if props.get("workspaceId"):
                destinations.append("LogAnalyticsWorkspace")
            if props.get("storageAccountId"):
                destinations.append("StorageAccount")
            if props.get("eventHubAuthorizationRuleId") or props.get("eventHubName"):
                destinations.append("EventHub")
            if props.get("marketplacePartnerId"):
                destinations.append("MarketplacePartner")

            entry = {
                "settingName": setting.get("name", "Unknown"),
                "enabledCategories": enabled_categories,
                "destinations": destinations
            }

            if enabled_categories and destinations:
                logging_enabled = True
                log_categories_found.extend(enabled_categories)
                configured_settings.append(entry)
            else:
                incomplete_settings.append(entry)

        if logging_enabled:
            pass_reasons.append(
                f"Backup logging is enabled: {len(configured_settings)} diagnostic setting(s) forwarding logs to a destination"
            )
            unique_categories = sorted(set(log_categories_found))
            if unique_categories:
                pass_reasons.append(f"Log categories: {', '.join(unique_categories[:5])}")
            destinations_found = sorted({d for s in configured_settings for d in s["destinations"]})
            if destinations_found:
                pass_reasons.append(f"Destinations: {', '.join(destinations_found)}")
        elif settings:
            fail_reasons.append(
                f"{len(settings)} diagnostic setting(s) found, but none have both an enabled log category and a delivery destination"
            )
            recommendations.append("Enable at least one log category and set a Log Analytics workspace, Storage Account, or Event Hub destination")
        else:
            fail_reasons.append("Backup logging is not enabled or diagnostic settings not configured")
            recommendations.append("Enable diagnostic settings for backup resources and configure log categories")

        return create_response(
            result={criteriaKey: logging_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "loggingEnabled": logging_enabled,
                "vaultResponsesEvaluated": len(responses),
                "diagnosticSettingsFound": len(settings),
                "logCategoriesCount": len(set(log_categories_found))
            },
            additional_findings=incomplete_settings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
