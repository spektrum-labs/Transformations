"""
Transformation: isBackupTested
Vendor: Datto BCDR
Category: Backup / Data Protection

Checks whether Datto BCDR backups have been tested via Screenshot Verification or restore tests.
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
                "transformationId": "isBackupTested",
                "vendor": "Datto",
                "category": "Backup"
            }
        }
    }


def transform(input):
    criteriaKey = "isBackupTested"

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

        # Check for backup verification/testing
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        ) if isinstance(data, dict) else []

        is_backup_tested = False
        tested_count = 0

        for device in devices:
            if isinstance(device, list):
                device = device[0] if len(device) > 0 else {}

            # Check Screenshot Verification (Datto's automated backup verification)
            screenshot = device.get("screenshotVerification", device.get("lastScreenshotStatus", {}))
            if isinstance(screenshot, dict):
                if screenshot.get("success", False) or screenshot.get("verified", False):
                    is_backup_tested = True
                    tested_count += 1
                    continue
            elif isinstance(screenshot, bool) and screenshot:
                is_backup_tested = True
                tested_count += 1
                continue
            elif isinstance(screenshot, str) and screenshot.lower() in ["success", "verified", "passed"]:
                is_backup_tested = True
                tested_count += 1
                continue

            # Check for restore tests
            restore_test = device.get("lastRestoreTest", device.get("restoreTestStatus", {}))
            if isinstance(restore_test, dict):
                if restore_test.get("success", False) or restore_test.get("completed", False):
                    is_backup_tested = True
                    tested_count += 1
            elif restore_test:
                is_backup_tested = True
                tested_count += 1

        if is_backup_tested:
            pass_reasons.append(f"Backup testing verified with {tested_count} devices tested")
            pass_reasons.append("Datto Screenshot Verification or restore tests passed")
        else:
            fail_reasons.append("No Datto BCDR backup verification tests found")
            recommendations.append("Enable Screenshot Verification for automated backup testing")

        return create_response(
            result={criteriaKey: is_backup_tested},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalDevices": len(devices),
                "testedDevices": tested_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
