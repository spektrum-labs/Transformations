# isbackuptypesscheduled.py - Rubrik

import json
import ast

def transform(input):
    """
    Analyzes SLA domain frequency configurations to validate scheduled backup types
    (hourly, daily, weekly, monthly, yearly).

    Parameters:
        input (dict): The JSON data from Rubrik listSLADomains endpoint.

    Returns:
        dict: A dictionary with backup schedule information by type.
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

        is_scheduled = False
        has_hourly = False
        has_daily = False
        has_weekly = False
        has_monthly = False
        has_yearly = False
        total_sla_count = 0
        scheduled_sla_count = 0

        # Check for SLA domains
        sla_domains = (
            data.get("slaDomains", []) or
            data.get("data", []) or
            data.get("items", [])
        )

        if isinstance(sla_domains, list):
            total_sla_count = len(sla_domains)

            for sla in sla_domains:
                if isinstance(sla, list):
                    sla = sla[0] if len(sla) > 0 else {}

                sla_has_schedule = False

                # Check frequencies array (Rubrik's SLA structure)
                frequencies = sla.get("frequencies", [])
                if isinstance(frequencies, list):
                    for freq in frequencies:
                        if isinstance(freq, dict):
                            freq_type = freq.get("timeUnit", freq.get("type", "")).lower()
                            retention = freq.get("retention", 0)

                            if freq_type == "hourly" or "hour" in freq_type:
                                has_hourly = True
                                sla_has_schedule = True
                            elif freq_type == "daily" or "day" in freq_type:
                                has_daily = True
                                sla_has_schedule = True
                            elif freq_type == "weekly" or "week" in freq_type:
                                has_weekly = True
                                sla_has_schedule = True
                            elif freq_type == "monthly" or "month" in freq_type:
                                has_monthly = True
                                sla_has_schedule = True
                            elif freq_type == "yearly" or "year" in freq_type:
                                has_yearly = True
                                sla_has_schedule = True

                            if retention and retention > 0:
                                sla_has_schedule = True

                # Check for individual frequency fields
                if sla.get("hourlyFrequency") or sla.get("hourly"):
                    has_hourly = True
                    sla_has_schedule = True
                if sla.get("dailyFrequency") or sla.get("daily"):
                    has_daily = True
                    sla_has_schedule = True
                if sla.get("weeklyFrequency") or sla.get("weekly"):
                    has_weekly = True
                    sla_has_schedule = True
                if sla.get("monthlyFrequency") or sla.get("monthly"):
                    has_monthly = True
                    sla_has_schedule = True
                if sla.get("yearlyFrequency") or sla.get("yearly"):
                    has_yearly = True
                    sla_has_schedule = True

                # Check for backup windows
                if sla.get("allowedBackupWindows") or sla.get("firstFullAllowedBackupWindows"):
                    sla_has_schedule = True

                # Check local retention
                if sla.get("localRetentionLimit") and sla.get("localRetentionLimit") > 0:
                    sla_has_schedule = True

                if sla_has_schedule:
                    scheduled_sla_count += 1
                    is_scheduled = True

        return {
            "isBackupTypesScheduled": is_scheduled,
            "hasHourlyBackup": has_hourly,
            "hasDailyBackup": has_daily,
            "hasWeeklyBackup": has_weekly,
            "hasMonthlyBackup": has_monthly,
            "hasYearlyBackup": has_yearly,
            "scheduledSLACount": scheduled_sla_count,
            "totalSLACount": total_sla_count
        }

    except json.JSONDecodeError:
        return {"isBackupTypesScheduled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTypesScheduled": False, "error": str(e)}
