"""
Transformation: confirmedLicensePurchased
Vendor: Rubrik  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether a valid Rubrik CDM license has been purchased and the cluster is actively deployed.
Checks GET /api/v1/cluster/me for a non-empty cluster id and version, confirming the product
is licensed and operational.
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
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Rubrik",
                "category": "control-objectives-for-information-and-related-technologies-cobit"
            }
        }
    }


def evaluate(data):
    try:
        cluster_id = data.get("id", "")
        version = data.get("version", "")
        api_version = data.get("apiVersion", "")
        cluster_name = data.get("name", "")
        accepted_eula = data.get("acceptedEulaVersion", "")
        latest_eula = data.get("latestEulaVersion", "")

        has_cluster_id = isinstance(cluster_id, str) and len(cluster_id) > 0
        has_version = isinstance(version, str) and len(version) > 0
        eula_accepted = False
        if accepted_eula and latest_eula:
            eula_accepted = accepted_eula == latest_eula
        elif accepted_eula:
            eula_accepted = True

        license_confirmed = has_cluster_id and has_version

        return {
            "confirmedLicensePurchased": license_confirmed,
            "clusterId": cluster_id,
            "clusterName": cluster_name,
            "clusterVersion": version,
            "apiVersion": api_version,
            "acceptedEulaVersion": accepted_eula,
            "latestEulaVersion": latest_eula,
            "eulaUpToDate": eula_accepted,
            "hasClusterId": has_cluster_id,
            "hasVersion": has_version
        }
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
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

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        cluster_id = eval_result.get("clusterId", "")
        cluster_name = eval_result.get("clusterName", "")
        cluster_version = eval_result.get("clusterVersion", "")
        api_version = eval_result.get("apiVersion", "")
        accepted_eula = eval_result.get("acceptedEulaVersion", "")
        latest_eula = eval_result.get("latestEulaVersion", "")
        eula_up_to_date = eval_result.get("eulaUpToDate", False)
        has_cluster_id = eval_result.get("hasClusterId", False)
        has_version = eval_result.get("hasVersion", False)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append(
                "Rubrik CDM cluster is operational and returned a valid cluster ID and version, "
                "confirming a licensed product is actively deployed."
            )
            if cluster_name:
                pass_reasons.append("Cluster name: " + cluster_name)
            if cluster_version:
                additional_findings.append("Rubrik CDM version: " + cluster_version)
            if api_version:
                additional_findings.append("REST API version: " + api_version)
            if eula_up_to_date:
                additional_findings.append(
                    "EULA is accepted and up to date (version: " + accepted_eula + ")."
                )
            elif accepted_eula and latest_eula and accepted_eula != latest_eula:
                additional_findings.append(
                    "EULA version mismatch: accepted=" + accepted_eula +
                    ", latest=" + latest_eula + ". Consider accepting the updated EULA."
                )
        else:
            if not has_cluster_id:
                fail_reasons.append(
                    "GET /api/v1/cluster/me did not return a valid cluster ID. "
                    "The Rubrik CDM cluster may not be properly licensed or accessible."
                )
            if not has_version:
                fail_reasons.append(
                    "GET /api/v1/cluster/me did not return a software version. "
                    "The Rubrik CDM cluster may not be properly licensed or accessible."
                )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append(
                "Verify that the Rubrik CDM cluster is fully operational and that a valid Rubrik "
                "license has been applied. Ensure the cluster address and credentials are correct."
            )

        return create_response(
            result={
                criteriaKey: result_value,
                "clusterId": cluster_id,
                "clusterName": cluster_name,
                "clusterVersion": cluster_version,
                "apiVersion": api_version,
                "eulaUpToDate": eula_up_to_date
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "clusterId": cluster_id,
                "clusterVersion": cluster_version,
                "confirmedLicensePurchased": result_value
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
