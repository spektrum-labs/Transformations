# is_backup_tested.py - Datto BCDR

import json
import ast

def transform(input):
    """
    Checks whether Datto BCDR backups have been tested via Screenshot Verification or restore tests.
    Returns: {"isBackupTested": bool}
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

        # Check for backup verification/testing
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        )

        is_backup_tested = False

        for device in devices:
            if isinstance(device, list):
                device = device[0] if len(device) > 0 else {}
            
            # Check Screenshot Verification (Datto's automated backup verification)
            screenshot = device.get("screenshotVerification", device.get("lastScreenshotStatus", {}))
            if isinstance(screenshot, dict):
                if screenshot.get("success", False) or screenshot.get("verified", False):
                    is_backup_tested = True
                    break
            elif isinstance(screenshot, bool) and screenshot:
                is_backup_tested = True
                break
            elif isinstance(screenshot, str) and screenshot.lower() in ["success", "verified", "passed"]:
                is_backup_tested = True
                break

            # Check for restore tests
            restore_test = device.get("lastRestoreTest", device.get("restoreTestStatus", {}))
            if isinstance(restore_test, dict):
                if restore_test.get("success", False) or restore_test.get("completed", False):
                    is_backup_tested = True
                    break
            elif restore_test:
                is_backup_tested = True
                break

        return {"isBackupTested": is_backup_tested}

    except json.JSONDecodeError:
        return {"isBackupTested": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}

