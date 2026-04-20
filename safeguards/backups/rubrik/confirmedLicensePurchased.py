"""
Transformation: confirmedLicensePurchased
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether at least one Rubrik cluster is connected and reporting an active status
in RSC, confirming that a licensed Rubrik deployment is in use.
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
                "category": "Backup"
            }
        }
    }


ACTIVE_STATUSES = ["CONNECTED", "ACTIVE", "OK", "RUNNING"]


def is_cluster_active(status):
    if not isinstance(status, str):
        return False
    return status.upper() in ACTIVE_STATUSES


def evaluate(data):
    try:
        clusters = []
        raw_nodes = data.get("nodes", [])
        if isinstance(raw_nodes, list):
            for node in raw_nodes:
                if isinstance(node, dict) and ("encryptionEnabled" in node or "productType" in node or "version" in node):
                    clusters.append(node)
        if not clusters:
            cluster_data = data.get("clusterConnection", {})
            if isinstance(cluster_data, dict):
                raw_nodes = cluster_data.get("nodes", [])
                if isinstance(raw_nodes, list):
                    clusters = raw_nodes

        total_clusters = len(clusters)
        active_clusters = []
        inactive_clusters = []

        for cluster in clusters:
            name = cluster.get("name", "unknown")
            status = cluster.get("status", "")
            if is_cluster_active(status):
                active_clusters.append(name)
            else:
                inactive_clusters.append(name + " (" + str(status) + ")")

        active_count = len(active_clusters)
        is_licensed = total_clusters > 0

        return {
            "confirmedLicensePurchased": is_licensed,
            "totalClusters": total_clusters,
            "activeClusters": active_count,
            "activeClusterNames": active_clusters,
            "inactiveClusters": len(inactive_clusters),
            "inactiveClusterDetails": inactive_clusters
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        findings = []
        if result_value:
            pass_reasons.append(
                "Licensed Rubrik deployment confirmed: " +
                str(eval_result.get("totalClusters", 0)) +
                " cluster(s) registered in RSC"
            )
            if eval_result.get("activeClusters", 0) > 0:
                pass_reasons.append(
                    str(eval_result.get("activeClusters", 0)) + " cluster(s) reporting active status"
                )
                names = eval_result.get("activeClusterNames", [])
                if names:
                    findings.append("Active clusters: " + ", ".join(names))
            if eval_result.get("inactiveClusters", 0) > 0:
                details = eval_result.get("inactiveClusterDetails", [])
                findings.append(
                    str(eval_result.get("inactiveClusters", 0)) +
                    " cluster(s) not in active status: " + ", ".join(details)
                )
        else:
            fail_reasons.append("No Rubrik clusters found in RSC; a licensed deployment could not be confirmed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Connect at least one Rubrik cluster to Rubrik Security Cloud to confirm "
                "a licensed deployment is in use"
            )
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=findings,
            input_summary={
                "totalClusters": eval_result.get("totalClusters", 0),
                "activeClusters": eval_result.get("activeClusters", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
