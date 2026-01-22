# isbackuploggingenabled.py - Rubrik

import json
import ast

def transform(input):
    """
    Checks if Rubrik event logging is enabled and events are being captured
    for audit purposes.

    Parameters:
        input (dict): The JSON data from Rubrik listEvents endpoint.

    Returns:
        dict: A dictionary indicating if backup logging is enabled.
    """
    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        # Parse input
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        is_logging_enabled = False
        event_count = 0

        # Check for events list
        events = (
            data.get("events", []) or
            data.get("data", []) or
            data.get("items", [])
        )

        if isinstance(events, list):
            event_count = len(events)
            if event_count > 0:
                is_logging_enabled = True

                # Verify events have expected fields
                for event in events[:5]:  # Check first 5 events
                    if isinstance(event, dict):
                        has_event_data = (
                            event.get("id") or
                            event.get("eventType") or
                            event.get("objectType") or
                            event.get("status") or
                            event.get("time")
                        )
                        if has_event_data:
                            is_logging_enabled = True
                            break

        # Check for explicit logging configuration
        if data.get("loggingEnabled") or data.get("auditLoggingEnabled"):
            is_logging_enabled = True

        return {
            "isBackupLoggingEnabled": is_logging_enabled,
            "eventCount": event_count
        }

    except json.JSONDecodeError:
        return {"isBackupLoggingEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupLoggingEnabled": False, "error": str(e)}
