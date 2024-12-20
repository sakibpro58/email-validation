from flask import Flask, request, jsonify
import source_code as sc
from suggestion import suggest_email_domain
from popular_domains import emailDomains
import whois

app = Flask(__name__)

# Helper function for email validation
def validate_single_email(email):
    try:
        result = {
            "email": email,
            "syntaxValidation": sc.is_valid_email(email),
        }
        if result["syntaxValidation"]:
            domain_part = email.split('@')[1]
            result["MXRecord"] = sc.has_valid_mx_record(domain_part)
            result["smtpConnection"] = sc.verify_email(email) if result["MXRecord"] else False
            result["isTemporary"] = sc.is_disposable(domain_part)
            result["suggestedDomains"] = suggest_email_domain(domain_part, emailDomains)
            
            try:
                whois_info = whois.whois(domain_part)
                result["domainInfo"] = {
                    "registrar": whois_info.registrar,
                    "server": whois_info.whois_server,
                    "country": whois_info.country,
                }
            except Exception as whois_error:
                result["domainInfo"] = "Could not retrieve domain information"
                print(f"WHOIS lookup error for {domain_part}: {whois_error}")
            
            result["status"] = "Valid" if all(
                [result["syntaxValidation"], result["MXRecord"], result["smtpConnection"], not result["isTemporary"]]
            ) else "Invalid"
        else:
            result["status"] = "Invalid"
        
        # Convert any NumPy objects to native Python types
        result = _convert_numpy_objects(result)
        return result
    except Exception as e:
        print(f"Error validating email {email}: {e}")
        return {"email": email, "status": "Error", "error": str(e)}

# Utility function to handle NumPy objects
def _convert_numpy_objects(data):
    if isinstance(data, dict):
        return {key: _convert_numpy_objects(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [_convert_numpy_objects(item) for item in data]
    elif isinstance(data, (int, float, str, bool)) or data is None:
        return data
    elif hasattr(data, "tolist"):  # Handle NumPy arrays or similar
        return data.tolist()
    else:
        return str(data)  # Fallback for other types

# Endpoint for single email validation
@app.route('/api/v1/validate', methods=['GET'])
def validate_email():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "Email parameter is required"}), 400
    result = validate_single_email(email)
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
