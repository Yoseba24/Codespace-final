
# app.py
from flask import Flask, make_response, request
import os
import hmac
import hashlib
import logging
import base64

app = Flask(__name__)

# Desactivar logs que puedan filtrar información sensible en la salida
app.logger.disabled = True
werk = logging.getLogger('werkzeug')
werk.disabled = True

def hmac_sha256_hex(key: str, msg: str) -> str:
    return hmac.new(key.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

def sha256_hex(msg: str) -> str:
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()

def secure_compare(a: str, b: str) -> bool:
    """Comparación resistente a timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

@app.after_request
def secure_headers(response):
    # Evitar cache en cliente / proxies
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    response.headers["Pragma"] = "no-cache"
    # Headers de seguridad básicos
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    # Eliminar cabeceras innecesarias
    response.headers.pop("Server", None)
    return response

def check_basic_auth(auth_header: str) -> bool:
    """
    Verifica Authorization: Basic base64(user:pass)
    Comprueba contra AUTH_USER / AUTH_PASS (desde secrets).
    """
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    try:
        b64 = auth_header.split(" ", 1)[1].strip()
        decoded = base64.b64decode(b64).decode("utf-8")
        user, password = decoded.split(":", 1)
    except Exception:
        return False

    required_user = os.environ.get("AUTH_USER")
    required_pass = os.environ.get("AUTH_PASS")

    if not required_user or not required_pass:
        # Si no hay credenciales configuradas, denegamos por seguridad.
        return False

    # Comparamos de forma segura para evitar timing attacks
    return secure_compare(user, required_user) and secure_compare(password, required_pass)

@app.route("/")
def home():
    # Comprobamos que los secrets necesarios existen en entorno
    missing = [k for k in ("MI_SECRETO", "AUTH_USER", "AUTH_PASS") if not os.environ.get(k)]
    if missing:
        return make_response(f"Error: faltan secretos en el entorno: {', '.join(missing)}", 500)

    # Autenticación básica
    auth_header = request.headers.get("Authorization", "")
    if not check_basic_auth(auth_header):
        resp = make_response("Acceso no autorizado. Introduce usuario y contraseña.", 401)
        resp.headers["WWW-Authenticate"] = 'Basic realm="Acceso restringido"'
        return resp

    # Si pasa la auth, calculamos el código seguro del secreto
    secret = os.environ.get("MI_SECRETO")
    signing_key = os.environ.get("SIGNING_KEY")

    if signing_key:
        encoded = hmac_sha256_hex(signing_key, secret)
        method = "HMAC-SHA256"
    else:
        encoded = sha256_hex(secret)
        method = "SHA256"

    # No registramos ni mostramos el secreto en claro nunca.
    resp_text = f"Hola yra0005@alu.medac.es — este es mi secreto ({method}): {encoded}"
    return make_response(resp_text, 200)

if __name__ == "__main__":
    # Ejecutar en Codespaces en el puerto 8000
    app.run(host="0.0.0.0", port=8000, debug=False)
    
    