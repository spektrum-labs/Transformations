# isbackupencrypted.py - CrashPlan

import json
import ast

def transform(input):
    """
    Checks organization security settings for encryption configuration.
    CrashPlan encrypts all data by default using AES-256 encryption.

    Parameters:
        input (dict): The JSON data from CrashPlan getSecuritySettings endpoint.

    Returns:
        dict: A dictionary indicating if backup encryption is enabled.
    """
    try:
        def parse_input(input):
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
        data = parse_input(input)

        # Drill down past response/result wrappers if present
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)
        data = data.get("securitySettings", data)

        # A RESPONSE THAT CARRIES NO SETTINGS IS NOT A RESPONSE ABOUT THIS TENANT. {} parses
        # cleanly, so it used to fall straight through to the vendor default below and
        # report isBackupEncrypted TRUE -- the same fail-open as the parse-error path, one
        # step further in. "No override was present" and "nothing was returned" are
        # different facts and only the first supports the default.
        # An ERROR ENVELOPE is not settings either, and it is the likeliest thing to arrive
        # here in practice. {"error": "401 unauthorized"} is a non-empty dict carrying no
        # encryption keys, so it too used to reach the vendor default and report TRUE --
        # a rejected credential reported as encrypted backups.
        error_keys = ("error", "errors", "errorMessage", "errorType", "fault", "PSError")
        looks_like_error = any(data.get(k) for k in error_keys) if isinstance(data, dict) else False
        try:
            status = int(data.get("statusCode") or data.get("status_code") or 0) if isinstance(data, dict) else 0
        except (TypeError, ValueError):
            status = 0
        # A NON-EMPTY DICT IS NOT A CRASHPLAN SETTINGS RESPONSE. Requiring only
        # non-emptiness let any unrelated payload through to the vendor default:
        # measured 2026-09-22, {"hello": "world"} reported isBackupEncrypted TRUE. The
        # body must name at least one setting this transform actually reads, or there is
        # nothing here about this tenant's encryption to read.
        known_keys = ("archiveKeyRule", "encryptionEnabled", "securityKeyLocked",
                      "securityKeyType", "orgSecurityInfo")
        names_a_setting = any(k in data for k in known_keys) if isinstance(data, dict) else False
        if not isinstance(data, dict) or not data or looks_like_error or status >= 400 or not names_a_setting:
            return {
                "isBackupEncrypted": False,
                "encryptionManaged": False,
                "note": "CrashPlan returned no readable security settings (empty body or an "
                        "error response), so encryption was not verified for this tenant. "
                        "CrashPlan does encrypt by default, but that is a product fact and "
                        "not a reading of this estate.",
            }

        # CrashPlan always encrypts data by default
        # Check for encryption-related settings
        encryption_enabled = True  # CrashPlan default
        encryption_key_type = "archive"  # Default key type

        # Check for custom archive key settings
        if "archiveKeyRule" in data:
            encryption_key_type = data.get("archiveKeyRule", "archive")

        # Check for encryption override settings
        if "encryptionEnabled" in data:
            encryption_enabled = data.get("encryptionEnabled", True)

        # Check security key configuration
        security_key_locked = data.get("securityKeyLocked", False)
        security_key_type = data.get("securityKeyType", "")

        # Check for organization-level encryption settings
        org_security = data.get("orgSecurityInfo", {})
        if org_security:
            if "encryptionEnabled" in org_security:
                encryption_enabled = org_security.get("encryptionEnabled", True)

        # Determine encryption management type
        is_managed = encryption_key_type in ["accountPassword", "archive"]
        is_custom_key = encryption_key_type == "customKey"

        return {
            "isBackupEncrypted": encryption_enabled,
            "encryptionKeyType": encryption_key_type,
            "encryptionManaged": is_managed,
            "customKeyUsed": is_custom_key,
            "securityKeyLocked": security_key_locked
        }

    except json.JSONDecodeError:
        return {"isBackupEncrypted": False, "error": "Invalid JSON"}
    except Exception as e:
        # THE ERROR PATH MUST NOT ASSERT THE CONTROL HOLDS. This branch used to return
        # isBackupEncrypted TRUE with a note reading "CrashPlan encrypts all data by
        # default", which meant transform(None) -- no response read at all -- reported
        # backups as encrypted, and said so with the same confidence as a real reading.
        # Measured 2026-09-21: transform(None) returned {"isBackupEncrypted": true,
        # "parseError": "Input must be JSON string, bytes, or dict"}. A criterion answered
        # from a parse failure is not a measurement of this customer's estate.
        #
        # The vendor-default reasoning is not wrong and is kept where it belongs: in the
        # success path above, which applies it to a response that WAS read and that did not
        # explicitly disable encryption. What is removed is its use as a fallback for
        # having read nothing. A product fact is not evidence about a tenant.
        return {
            "isBackupEncrypted": False,
            "encryptionManaged": False,
            "note": "Could not read CrashPlan security settings, so encryption was not "
                    "verified for this tenant. CrashPlan does encrypt by default, but that "
                    "is a product fact and not a reading of this estate -- re-run once the "
                    "call succeeds.",
            "parseError": str(e)
        }
