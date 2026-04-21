"""
Transformation: isBackupTested
Vendor: Rubrik  |  Category: nydfs / Backups
Evaluates: Whether backup snapshots are being taken and can be considered tested.
Checks that at least one protected (snappable) object has a non-zero
snapshotDistribution.totalCount, confirming backups have executed successfully.
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupTested", "vendor": "Rubrik", "category": "nydfs/Backups"}
        }
    }


def evaluate(data):
    try:
        snappable_nodes = data.get("data", [])
        if not isinstance(snappable_nodes, list):
            snappable_nodes = []

        total_objects = len(snappable_nodes)
        objects_with_snapshots = 0
        total_snapshots = 0
        total_scheduled = 0
        total_on_demand = 0
        objects_without_snapshots = 0

        for node in snappable_nodes:
            dist = node.get("snapshotDistribution", None)
            if dist is None:
                objects_without_snapshots = objects_without_snapshots + 1
                continue
            total_count = dist.get("totalCount", 0)
            scheduled_count = dist.get("scheduledCount", 0)
            on_demand_count = dist.get("onDemandCount", 0)
            total_snapshots = total_snapshots + total_count
            total_scheduled = total_scheduled + scheduled_count
            total_on_demand = total_on_demand + on_demand_count
            if total_count > 0:
                objects_with_snapshots = objects_with_snapshots + 1
            else:
                objects_without_snapshots = objects_without_snapshots + 1

        result = objects_with_snapshots > 0

        score = 0
        if total_objects > 0:
            score = (objects_with_snapshots * 100) // total_objects

        return {
            "isBackupTested": result,
            "totalProtectedObjects": total_objects,
            "objectsWithSnapshots": objects_with_snapshots,
            "objectsWithoutSnapshots": objects_without_snapshots,
            "totalSnapshotCount": total_snapshots,
            "scheduledSnapshotCount": total_scheduled,
            "onDemandSnapshotCount": total_on_demand,
            "scoreInPercentage": score
        }
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupTested"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = eval_result.get("totalProtectedObjects", 0)
        with_snaps = eval_result.get("objectsWithSnapshots", 0)
        without_snaps = eval_result.get("objectsWithoutSnapshots", 0)
        total_snaps = eval_result.get("totalSnapshotCount", 0)
        scheduled = eval_result.get("scheduledSnapshotCount", 0)
        on_demand = eval_result.get("onDemandSnapshotCount", 0)
        score = eval_result.get("scoreInPercentage", 0)

        additional_findings.append("Total snappable objects: " + str(total))
        additional_findings.append("Objects with at least one snapshot: " + str(with_snaps))
        additional_findings.append("Objects with zero snapshots: " + str(without_snaps))
        additional_findings.append("Total snapshots across all objects: " + str(total_snaps))
        additional_findings.append("Scheduled snapshots: " + str(scheduled) + ", On-demand snapshots: " + str(on_demand))
        additional_findings.append("Snapshot coverage score: " + str(score) + "%")

        if result_value:
            pass_reasons.append("At least one protected object has snapshots, confirming backups have executed successfully.")
            pass_reasons.append(str(with_snaps) + " of " + str(total) + " objects have snapshots (" + str(score) + "% coverage).")
            pass_reasons.append("Total snapshots recorded: " + str(total_snaps) + " (" + str(scheduled) + " scheduled, " + str(on_demand) + " on-demand).")
        else:
            if total == 0:
                fail_reasons.append("No snappable (protected) objects were returned by the Rubrik API.")
            else:
                fail_reasons.append("None of the " + str(total) + " snappable objects have any snapshots recorded.")
                fail_reasons.append("Backups do not appear to have executed successfully for any protected object.")
            recommendations.append("Assign SLA domains to objects and trigger backup jobs so that snapshots are created.")
            recommendations.append("Review Rubrik backup job history and resolve any failures preventing snapshot creation.")
            recommendations.append("Consider running on-demand snapshots to validate backup functionality immediately.")

        extra_fields = {
            "totalProtectedObjects": total,
            "objectsWithSnapshots": with_snaps,
            "objectsWithoutSnapshots": without_snaps,
            "totalSnapshotCount": total_snaps,
            "scheduledSnapshotCount": scheduled,
            "onDemandSnapshotCount": on_demand,
            "scoreInPercentage": score
        }

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalProtectedObjects": total, "objectsWithSnapshots": with_snaps, "scoreInPercentage": score}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
