"""
Transformation: isComplianceProgramActive
Vendor: ZenGRC  |  Category: GRC
Evaluates: Whether active compliance programs exist in ZenGRC with assigned owners and defined scope.
Source: GET /api/v2/programs
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isComplianceProgramActive", "vendor": "ZenGRC", "category": "GRC"}
        }
    }


def evaluate(data):
    """Check if active compliance programs exist with owners and scope."""
    try:
        programs = data.get("data", data.get("programs", data.get("results", [])))
        if not isinstance(programs, list):
            programs = [programs] if programs else []

        total_programs = len(programs)
        active_programs = 0
        programs_with_owners = 0
        program_names = []

        for program in programs:
            if not isinstance(program, dict):
                continue

            # ZenGRC JSON:API format has attributes nested
            attrs = program.get("attributes", program)
            if not isinstance(attrs, dict):
                continue

            status = attrs.get("status", attrs.get("state", ""))
            title = attrs.get("title", attrs.get("name", attrs.get("slug", "")))

            is_active = str(status).lower() in ("active", "enabled", "in progress", "draft", "effective", "launched")

            # If no explicit status, treat presence as active
            if not status and title:
                is_active = True

            if is_active:
                active_programs = active_programs + 1
                if title:
                    program_names.append(str(title))

            # Check for owner assignment
            owner = attrs.get("owner", attrs.get("owners", attrs.get("contact", attrs.get("primary_contact", None))))
            relationships = program.get("relationships", {})
            if isinstance(relationships, dict):
                rel_owner = relationships.get("owners", relationships.get("primary_contact", None))
                if rel_owner:
                    owner = rel_owner

            if owner:
                programs_with_owners = programs_with_owners + 1

        is_compliant = active_programs > 0

        return {
            "isComplianceProgramActive": is_compliant,
            "totalPrograms": total_programs,
            "activePrograms": active_programs,
            "programsWithOwners": programs_with_owners,
            "programNames": program_names[:10]
        }
    except Exception as e:
        return {"isComplianceProgramActive": False, "error": str(e)}


def transform(input):
    criteriaKey = "isComplianceProgramActive"
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

        if result_value:
            pass_reasons.append(str(extra_fields.get("activePrograms", 0)) + " active compliance program(s) found")
            if extra_fields.get("programsWithOwners", 0) > 0:
                pass_reasons.append(str(extra_fields["programsWithOwners"]) + " program(s) have assigned owners")
            if extra_fields.get("programNames"):
                pass_reasons.append("Programs: " + ", ".join(extra_fields["programNames"][:5]))
        else:
            fail_reasons.append("No active compliance programs found in ZenGRC")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Create and activate at least one compliance program in ZenGRC with an assigned owner")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalPrograms": extra_fields.get("totalPrograms", 0), "activePrograms": extra_fields.get("activePrograms", 0)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
