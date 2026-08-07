from crypto import crypto


def calculate_risk(payload):

    score = 100

    score -= payload.get("late_payments", 0) * 20
    score -= payload.get("existing_loans", 0) * 10

    if payload.get("income", 0) > 100000:
        score += 10

    if payload.get("age", 0) < 25:
        score -= 10

    return {
        "customer_id": payload.get("customer_id"),
        "risk_score": score,
        "eligible": score >= 70,
    }


def process_request(request):
    
    operation = request.get("operation")

    if operation == "get_public_key":

        return {
            "public_key": crypto.get_public_key()
        }

    elif operation == "risk_score":

        return calculate_risk(request["payload"])

    return {
        "error": "Unknown operation"
    }
