from flask import Flask, request, jsonify
import source_code as sc
from suggestion import suggest_email_domain
from popular_domains import emailDomains
import pandas as pd
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
        return result
    except Exception as e:
        print(f"Error validating email {email}: {e}")
        return {"email": email, "status": "Error", "error": str(e)}

# Endpoint for single email validation
@app.route('/api/v1/validate', methods=['GET'])
def validate_email():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "Email parameter is required"}), 400
    result = validate_single_email(email)
    return jsonify(result)

# Endpoint for bulk email validation
@app.route('/api/v1/bulk-validate', methods=['POST'])
def bulk_validate():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "File parameter is required"}), 400

    file_extension = file.filename.split('.')[-1].lower()
    try:
        if file_extension == 'csv':
            df = pd.read_csv(file)
        elif file_extension == 'xlsx':
            df = pd.read_excel(file)
        elif file_extension == 'txt':
            df = pd.read_csv(file, header=None, names=["email"])
        else:
            return jsonify({"error": "Unsupported file format. Use CSV, XLSX, or TXT."}), 400

        results = []
        for email in df.iloc[:, 0]:
            email = email.strip()
            results.append(validate_single_email(email))

        return jsonify(results)

    except Exception as e:
        print(f"Error processing bulk file: {e}")
        return jsonify({"error": f"Failed to process file: {str(e)}"}), 500

# Main application entry point
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
