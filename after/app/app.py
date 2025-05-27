
from flask import Flask, request, jsonify
import jwt
from datetime import datetime, timezone

app = Flask(__name__)

def format_jwt(decoded):
    for key in ['exp', 'iat', 'nbf']:
        if key in decoded:
            decoded[key] = datetime.fromtimestamp(decoded[key], tz=timezone.utc).isoformat().replace("+00:00", "Z")
    return decoded

@app.route("/")
def index():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing token", "created_at": datetime.now().isoformat() +"Z"}), 401
    token = auth_header.split()[1]
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return jsonify({"message": "Welcome!", "user": format_jwt(decoded), "created_at": datetime.now().isoformat() +"Z"})
    except Exception as e:
        return jsonify({"error": str(e), "created_at": datetime.now().isoformat() +"Z"}), 400


@app.after_request
def set_security_headers(response):
    # Prevent Mime Type Sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Set Permissions Policy
    response.headers['Permissions-Policy'] = "geolocation=(), microphone=(), camera=()"
    # Remove or overwrite Server header
    response.headers['Server'] = ""
    # Set X-Frame-Options to prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Set X-XSS-Protection header
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Set Strict-Transport-Security header
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Set Referrer-Policy header
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    # Set Content-Security-Policy header
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
    # Add Cross-Origin-Resource-Policy header
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    # ...existing headers...
    response.headers['Cache-Control'] = 'no-store'
    return response



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
