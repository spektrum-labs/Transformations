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
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        vaults = data
    elif isinstance(data, dict):
        vaults = data.get("BackupVaultList") or []
    else:
        vaults = []

    regions = []
    arns_seen = []
    for v in vaults:
        if not isinstance(v, dict):
            continue
        arn = v.get("BackupVaultArn") or ""
        arns_seen.append(arn)
        parts = arn.split(":")
        # arn:aws:backup:REGION:account:backup-vault:name
        if len(parts) >= 4 and parts[0] == "arn":
            region = parts[3]
            if region and region not in regions:
                regions.append(region)

    region_count = len(regions)

    input_summary = {
        "totalVaults": len(vaults),
        "distinctRegions": region_count,
        "regions": regions,
    }

    if region_count > 0:
        pass_reasons = [
            f"Found {len(vaults)} backup vault(s) spanning {region_count} distinct AWS region(s): {', '.join(regions)}, derived from BackupVaultArn values."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "No backup vaults with a parseable BackupVaultArn were found in the ListBackupVaults response, so no distinct regions could be identified."
        ]
        recommendations = [
            "Verify that ListBackupVaults is being called against each region of interest and that vaults exist with valid BackupVaultArn values."
        ]

    result = {
        "vaultRegionCount": region_count,
        "totalVaults": len(vaults),
        "regions": regions,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "vaultRegionCount",
            "vendor": "AWS Backup",
            "category": "backup",
        },
    )
