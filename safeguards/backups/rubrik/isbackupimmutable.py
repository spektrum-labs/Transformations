# isbackupimmutable.py - Rubrik

import json
import ast

def transform(input):
    """
    Checks SLA domains for retention lock settings indicating immutable
    backup configurations.

    Parameters:
        input (dict): The JSON data from Rubrik listSLADomains endpoint.

    Returns:
        dict: A dictionary indicating if backups are immutable.
    """
    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        # Parse input
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        is_immutable = False
        immutable_sla_count = 0
        total_sla_count = 0

        # Check for global immutability settings
        global_immutable = (
            data.get("immutableBackup", False) or
            data.get("immutabilityEnabled", False) or
            data.get("retentionLock", False)
        )

        if global_immutable:
            is_immutable = True

        # Check SLA domains for retention lock
        sla_domains = (
            data.get("slaDomains", []) or
            data.get("data", []) or
            data.get("items", [])
        )

        if isinstance(sla_domains, list):
            total_sla_count = len(sla_domains)

            for sla in sla_domains:
                if isinstance(sla, list):
                    sla = sla[0] if len(sla) > 0 else {}

                # Check for retention lock (Rubrik's immutability feature)
                retention_lock = sla.get("retentionLock", sla.get("isRetentionLocked", False))

                if isinstance(retention_lock, bool) and retention_lock:
                    is_immutable = True
                    immutable_sla_count += 1
                elif isinstance(retention_lock, dict):
                    if retention_lock.get("enabled", False) or retention_lock.get("isEnabled", False):
                        is_immutable = True
                        immutable_sla_count += 1

                # Check for immutability settings
                if sla.get("immutabilityEnabled", False) or sla.get("isImmutable", False):
                    is_immutable = True
                    immutable_sla_count += 1

                # Check for compliance retention
                if sla.get("complianceRetention", False):
                    is_immutable = True
                    immutable_sla_count += 1

                # Check for legal hold
                if sla.get("legalHold", False) or sla.get("isLegalHold", False):
                    is_immutable = True
                    immutable_sla_count += 1

        return {
            "isBackupImmutable": is_immutable,
            "immutableSLACount": immutable_sla_count,
            "totalSLACount": total_sla_count
        }

    except json.JSONDecodeError:
        return {"isBackupImmutable": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupImmutable": False, "error": str(e)}
