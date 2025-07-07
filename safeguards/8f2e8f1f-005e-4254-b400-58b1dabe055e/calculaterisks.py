# calculaterisks.py

import json

def transform(input):
    """
    Calculates the risk score based on the input data.
    Returns: {"riskThreshold": bool, "Count": int}
    """
    low_ratings = []
    lowest_rating = 0
    low_count = 0
    try:
        def _parse_input(input):
            if isinstance(input, str):
                return json.loads(input)
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")
        # Parse JSON if needed
        data = _parse_input(input)

        # Drill down past response/result wrappers if present
        data = data.get("response", data).get("result", data)

        #Get RatingDetails
        ratingDetails = data.get("rating_details", {})
        #Loop through each attribute & add rating less than 700 to rating array
        for attribute in ratingDetails:
            current_rating = getattr(ratingDetails[attribute], "rating", 0)
            if current_rating < 700:
                low_ratings.append(ratingDetails[attribute])
                if current_rating < lowest_rating:
                    lowest_rating = current_rating
                low_count += 1

        #Return the risk score and the count of attributes with rating less than 700
        return {"riskThreshold": lowest_rating, "count": low_count, "lowratings": low_ratings}
    except Exception as e:
        return {"riskThreshold": 0, "count": 0, "lowratings": [], "error": str(e)}
