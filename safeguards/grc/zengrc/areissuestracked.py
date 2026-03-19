"""
Transformation: areIssuesTracked
Vendor: ZenGRC  |  Category: GRC
Evaluates: Whether compliance issues and findings are tracked with assigned owners, due dates, and remediation status.
Source: GET /api/v2/issues
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "areIssuesTracked", "vendor": "ZenGRC", "category": "GRC"}
        }
    }


def evaluate(data):
    """Check if issues are tracked with owners, due dates, and remediation status."""
    try:
        issues = data.get("data", data.get("issues", data.get("results", [])))
        if not isinstance(issues, list):
            issues = [issues] if issues else []

        total_issues = len(issues)
        issues_with_owners = 0
        issues_with_due_dates = 0
        open_issues = 0
        remediated_issues = 0

        for issue in issues:
            if not isinstance(issue, dict):
                continue

            attrs = issue.get("attributes", issue)
            if not isinstance(attrs, dict):
                continue

            # Check status
            status = str(attrs.get("status", attrs.get("state", attrs.get("issue_status", "")))).lower()
            if status in ("open", "active", "in progress", "in_progress", "new", "assigned"):
                open_issues = open_issues + 1
            elif status in ("closed", "resolved", "remediated", "fixed", "completed"):
                remediated_issues = remediated_issues + 1

            # Check owner assignment
            owner = attrs.get("owner", attrs.get("owners", attrs.get("assigned_to", attrs.get("contact", None))))
            relationships = issue.get("relationships", {})
            if isinstance(relationships, dict):
                rel_owner = relationships.get("owners", relationships.get("contacts", None))
                if rel_owner:
                    owner = rel_owner
            if owner:
                issues_with_owners = issues_with_owners + 1

            # Check due dates
            due_date = attrs.get("due_on", attrs.get("dueOn", attrs.get("due_date", attrs.get("dueDate", attrs.get("end_date", "")))))
            if due_date:
                issues_with_due_dates = issues_with_due_dates + 1

        # Issues are tracked if there are issues with tracking attributes
        # Even zero issues is acceptable (no findings = good posture)
        is_tracked = total_issues == 0 or (issues_with_owners > 0 or issues_with_due_dates > 0)

        return {
            "areIssuesTracked": is_tracked,
            "totalIssues": total_issues,
            "openIssues": open_issues,
            "remediatedIssues": remediated_issues,
            "issuesWithOwners": issues_with_owners,
            "issuesWithDueDates": issues_with_due_dates
        }
    except Exception as e:
        return {"areIssuesTracked": False, "error": str(e)}


def transform(input):
    criteriaKey = "areIssuesTracked"
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
        additional_findings = []

        if result_value:
            if extra_fields.get("totalIssues", 0) == 0:
                pass_reasons.append("No compliance issues or findings recorded (clean posture)")
            else:
                pass_reasons.append(str(extra_fields["totalIssues"]) + " issue(s) tracked in ZenGRC")
                if extra_fields.get("issuesWithOwners", 0) > 0:
                    pass_reasons.append(str(extra_fields["issuesWithOwners"]) + " issue(s) have assigned owners")
                if extra_fields.get("issuesWithDueDates", 0) > 0:
                    pass_reasons.append(str(extra_fields["issuesWithDueDates"]) + " issue(s) have due dates set")
                if extra_fields.get("openIssues", 0) > 0:
                    additional_findings.append(str(extra_fields["openIssues"]) + " issue(s) still open")
                if extra_fields.get("remediatedIssues", 0) > 0:
                    additional_findings.append(str(extra_fields["remediatedIssues"]) + " issue(s) remediated")
        else:
            fail_reasons.append("Issues exist but lack proper tracking (no owners or due dates assigned)")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Assign owners and due dates to all open issues in ZenGRC")
            recommendations.append("Establish a remediation workflow for compliance findings")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalIssues": extra_fields.get("totalIssues", 0), "openIssues": extra_fields.get("openIssues", 0)},
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
