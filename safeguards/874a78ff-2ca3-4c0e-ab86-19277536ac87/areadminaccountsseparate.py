import json
import ast
def transform(input):
    """
    Selects secure Score from list returned and evaluates if
    transport rules are configured.

    Parameters:
        input (dict): The JSON data containing all secure Scores.

    Returns:
        dict: A dictionary summarizing recommended mail forwarding rules
    """

    # modify assignment to match specific criteriaKey
    criteriaKey = "areAdminAccountsSeparate"

    # modify assignment to match specific controlName
    controlName = "mdo_blockmailforward"

    try:
        def _parse_input(input):
            if isinstance(input, str):
                # First try to parse as literal Python string representation
                try:
                    # Use ast.literal_eval to safely parse Python literal
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                
                # If that fails, try to parse as JSON
                try:
                    # Replace single quotes with double quotes for JSON
                    #input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
                    
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        input = _parse_input(input)
        if 'response' in input:
            input = _parse_input(input['response'])
        if 'result' in input:
            input = _parse_input(input['result'])
            if 'apiResponse' in input:
                input = _parse_input(input['apiResponse'])
            if 'result' in input:
                input = _parse_input(input['result'])
        if 'Output' in input:
            input = _parse_input(input['Output'])
            
        # controlScores currently doesn't support filtering
        # return all controlScores and matches {controlName}
        value = input.get("value",[])
        control_scores = value[0].get("controlScores",[])
        matched_object_list = [i for i in control_scores if i['controlName'] == controlName]

        if len(matched_object_list) > 1:
           raise ValueError(f"More than one object has a controlName of {controlName}. (matched_object_count={len(matched_object_list)})")
        else: 
           matched_object = matched_object_list[0]
        
        default_value = False

        # currently scoreInPercentage must be 100.00 to be considered enforced/enabled
        score_in_percentage = matched_object.get("scoreInPercentage", 0.0)
        is_enabled = True if score_in_percentage == 100.00 else False

        # count = sum of objects/users currently under {controlName}
        count = matched_object.get("count", 0)
        
        # total = parent population of objects/users reachable by {controlName}
        total = matched_object.get("total", 0)

        return {
                    criteriaKey: is_enabled,
                    "scoreInPercentage": score_in_percentage,
                    "count": count,
                    "total": total
                }

    except Exception as e:
        return {criteriaKey: False,"error": str(e)}
    