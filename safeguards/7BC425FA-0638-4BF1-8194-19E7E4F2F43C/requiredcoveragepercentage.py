"""
Transformation: requiredCoveragePercentage
Vendor: Microsoft Defender / Endpoint Protection
Category: Endpoint Security

Evaluates percentage of endpoint protection coverage for eligible machines.
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
                    recommendations=None, input_summary=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "requiredCoveragePercentage",
                "vendor": "Microsoft Defender",
                "category": "Endpoint Security"
            }
        }
    }


def transform(input):
    criteriaKey = "requiredCoveragePercentage"

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

        # Get machine data from value array
        machine_data = []
        if isinstance(data, dict) and 'value' in data:
            machine_data = data['value']
        elif isinstance(data, list):
            machine_data = data

        eligibleMachines = [m for m in machine_data if isinstance(m, dict) and not m.get("isExcluded", False)]
        protectedMachines = [
            m for m in eligibleMachines
            if m.get("healthStatus") == "Active" and m.get("onboardingStatus") == "Onboarded"
        ]

        allDevices = len(machine_data)
        eligibleDevices = len(eligibleMachines)
        protectedDevices = len(protectedMachines)

        criteriaValue = (eligibleDevices == protectedDevices) and eligibleDevices > 0

        allDevicesPercentage = round((protectedDevices / allDevices) * 100) if allDevices > 0 else 0
        eligibleDevicesPercentage = round((protectedDevices / eligibleDevices) * 100) if eligibleDevices > 0 else 0

        if criteriaValue:
            pass_reasons.append(f"All eligible devices are protected: {protectedDevices}/{eligibleDevices} (100%)")
        else:
            if eligibleDevices > 0:
                fail_reasons.append(f"Not all eligible devices are protected: {protectedDevices}/{eligibleDevices} ({eligibleDevicesPercentage}%)")
                recommendations.append("Onboard remaining eligible devices to endpoint protection")
            else:
                fail_reasons.append("No eligible devices found")
                recommendations.append("Ensure devices are properly enrolled and not excluded")

        if allDevicesPercentage < 100:
            pass_reasons.append(f"Overall coverage: {protectedDevices}/{allDevices} devices ({allDevicesPercentage}%)")

        return create_response(
            result={
                criteriaKey: criteriaValue,
                "allDevicesPercentageofCoverage": allDevicesPercentage,
                "eligibleDevicesPercentageofCoverage": eligibleDevicesPercentage,
                "allDevices": allDevices,
                "eligibleDevices": eligibleDevices,
                "protectedDevices": protectedDevices
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "allDevices": allDevices,
                "eligibleDevices": eligibleDevices,
                "protectedDevices": protectedDevices
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
