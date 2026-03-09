"""
Transformation: isassetcoveragecomplete
Vendor: Axonius
Category: Asset Management

Validates that asset coverage meets minimum thresholds.
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
                "transformationId": "isassetcoveragecomplete",
                "vendor": "Axonius",
                "category": "Asset Management"
            }
        }
    }


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isAssetCoverageComplete": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        coverage_complete = False
        total_assets = 0
        covered_assets = 0
        coverage_percentage = 0

        # Check device data
        assets = data.get('assets', data.get('data', data.get('devices', [])))
        if isinstance(assets, list):
            total_assets = len(assets)

            # Check how many have adapters/sources
            for asset in assets:
                adapters = asset.get('adapters', asset.get('specific_data', []))
                if isinstance(adapters, list) and len(adapters) > 0:
                    covered_assets += 1
                elif isinstance(asset, dict) and len(asset) > 2:
                    covered_assets += 1

            if total_assets > 0:
                coverage_percentage = round((covered_assets / total_assets) * 100, 1)
                coverage_complete = coverage_percentage >= 80

                if coverage_complete:
                    pass_reasons.append(f"Asset coverage at {coverage_percentage}% ({covered_assets}/{total_assets})")
                else:
                    fail_reasons.append(f"Asset coverage at {coverage_percentage}% is below 80% threshold ({covered_assets}/{total_assets})")
                    recommendations.append("Increase adapter coverage to reach at least 80% of assets")
            else:
                fail_reasons.append("No assets found in the response")
                recommendations.append("Verify Axonius is configured to discover assets")

        elif 'page' in data:
            # Paginated response
            total_assets = data['page'].get('totalResources', 0)
            coverage_complete = total_assets > 0
            if coverage_complete:
                pass_reasons.append(f"{total_assets} total resources reported via pagination")
            else:
                fail_reasons.append("No resources found in paginated response")
        else:
            fail_reasons.append("No asset data found in response")
            recommendations.append("Ensure the Axonius devices API is returning data")

        return create_response(
            result={
                "isAssetCoverageComplete": coverage_complete,
                "totalAssets": total_assets,
                "coveredAssets": covered_assets,
                "coveragePercentage": coverage_percentage
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalAssets": total_assets,
                "coveredAssets": covered_assets,
                "coveragePercentage": coverage_percentage,
                "hasPaginatedResponse": 'page' in data if isinstance(data, dict) else False
            }
        )

    except Exception as e:
        return create_response(
            result={"isAssetCoverageComplete": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
