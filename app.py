"""
==========================================================
  LAB3 CRIPTO - Servidor Flask Vulnerable (Educativo)
==========================================================
  ADVERTENCIA: Este servidor es INTENCIONALMENTE INSEGURO.
  Solo usar en entornos controlados de laboratorio.
  
  Vulnerabilidades deliberadas:
  - Almacena contraseñas como MD5 (hash débil)
  - Acepta el hash directamente sin salt
  - Sin protección CSRF
  - Sin rate limiting
  - Mensajes de error descriptivos (información leakage)
  - Sin HTTPS
==========================================================
"""

from flask import Flask, request, jsonify, render_template, session
import json
import os
import hashlib
import re
from datetime import datetime

app = Flask(__name__)

# ============================================================
# VULNERABILIDAD #1: Secret key débil hardcodeada
# En producción real nunca hagas esto
# ============================================================
app.secret_key = "supersecret123"

# ============================================================
# Base de datos en memoria (simulada)
# En producción real se usaría una BD con contraseñas con salt+bcrypt
# Aquí almacenamos directamente el hash MD5 sin salt
# ============================================================
USERS_DB = {}

# Ruta al archivo JSON para persistencia simple (opcional)
USERS_FILE = "users.json"


def load_users():
    """Carga usuarios desde archivo JSON si existe."""
    global USERS_DB
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            USERS_DB = json.load(f)
    else:
        # Usuario de demostración pre-cargado
        # Contraseña: "password123" => MD5: 482c811da5d5b4bc6d497ffa98491e38
        USERS_DB = {
            "admin": {
                "username": "admin",
                # VULNERABILIDAD: Hash MD5 sin salt, generado con:
                # hashlib.md5("password123".encode()).hexdigest()
                "password_hash": "482c811da5d5b4bc6d497ffa98491e38",
                "email": "admin@lab.local",
                "created_at": "2024-01-01T00:00:00",
                "role": "admin"
            },
            "alice": {
                "username": "alice",
                # Contraseña: "alice2024" => MD5: calculado en cliente
                "password_hash": hashlib.md5("alice2024".encode()).hexdigest(),
                "email": "alice@lab.local",
                "created_at": "2024-01-01T00:00:00",
                "role": "user"
            }
        }
    return USERS_DB


def save_users():
    """Guarda usuarios en archivo JSON."""
    with open(USERS_FILE, "w") as f:
        json.dump(USERS_DB, f, indent=2)


# Cargamos usuarios al iniciar
load_users()


# ============================================================
# RUTAS PRINCIPALES
# ============================================================

@app.route("/")
def index():
    """Página principal - redirige al login."""
    return render_template("index.html")


@app.route("/login")
def login_page():
    """Página de login."""
    return render_template("login.html")


@app.route("/register")
def register_page():
    """Página de registro."""
    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    """Panel protegido (débilmente)."""
    # VULNERABILIDAD: Verificación de sesión muy básica
    if "username" not in session:
        return render_template("login.html", error="Debes iniciar sesión primero")
    return render_template("dashboard.html", username=session["username"])


@app.route("/policies")
def policies_page():
    """Página de políticas de seguridad (para evidenciar el incumplimiento)."""
    return render_template("policies.html")

# ============================================================
# API ENDPOINTS - Aquí ocurre la vulnerabilidad Pass-the-Hash
# ============================================================

@app.route("/api/register", methods=["POST"])
def api_register():
    """
    Endpoint de registro de usuario.
    
    VULNERABILIDAD DEMOSTRADA:
    El cliente envía el hash MD5 directamente.
    El servidor simplemente lo almacena tal cual.
    No hay salt, no hay re-hash en servidor.
    
    Request esperado (JSON):
    {
        "username": "usuario",
        "email": "correo@ejemplo.com",
        "password_hash": "md5_del_password"  <-- hash MD5 en texto plano
    }
    """
    data = request.get_json()
    
    # Log para demostración (en Burp Suite se puede ver esto)
    print(f"\n[{datetime.now()}] REGISTRO REQUEST:")
    print(f"  Username: {data.get('username')}")
    print(f"  Email: {data.get('email')}")
    print(f"  Hash recibido: {data.get('password_hash')}")  # <- esto es lo vulnerable
    
    username = data.get("username", "").strip().lower()
    email = data.get("email", "").strip()
    password_hash = data.get("password_hash", "").strip()
    
    # Validaciones básicas
    if not username or not email or not password_hash:
        return jsonify({
            "success": False,
            "error": "Todos los campos son requeridos",
            "received": data  # VULNERABILIDAD: devolvemos los datos recibidos (info leak)
        }), 400
        
    # Validación de formato MD5 (Defensa contra Inyección)
    if not re.match(r'^[a-fA-F0-9]{32}$', password_hash):
        return jsonify({
            "success": False,
            "error": "Formato de hash inválido. Se requiere MD5 (32 caracteres hexadecimales)."
        }), 400
    
    if username in USERS_DB:
        return jsonify({
            "success": False,
            "error": f"El usuario '{username}' ya existe"
        }), 409
    
    # VULNERABILIDAD: Guardamos el hash MD5 sin salt ni procesamiento adicional
    USERS_DB[username] = {
        "username": username,
        "password_hash": password_hash,  # <- hash MD5 crudo, sin salt
        "email": email,
        "created_at": datetime.now().isoformat(),
        "role": "user"
    }
    
    save_users()
    
    return jsonify({
        "success": True,
        "message": f"Usuario '{username}' registrado exitosamente",
        "stored_hash": password_hash,  # VULNERABILIDAD: confirmamos el hash (info leak)
        "algorithm": "MD5",            # VULNERABILIDAD: revelamos el algoritmo
        "note": "[EDUCATIVO] Hash MD5 almacenado SIN salt"
    }), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    """
    Endpoint de login.
    
    VULNERABILIDAD PASS-THE-HASH:
    El cliente envía el hash MD5 directamente.
    El servidor compara hash vs hash.
    Si un atacante captura el hash, puede enviarlo directamente sin conocer la contraseña.
    
    Request esperado (JSON):
    {
        "username": "usuario",
        "password_hash": "md5_del_password"  <-- aquí va el hash
    }
    
    ATAQUE: Si reemplazas password_hash por el hash correcto capturado previamente,
    el servidor te autenticará sin que conozcas la contraseña original.
    """
    data = request.get_json()
    
    # Log para demostración
    print(f"\n[{datetime.now()}] LOGIN REQUEST:")
    print(f"  Username: {data.get('username')}")
    print(f"  Hash recibido: {data.get('password_hash')}")
    
    username = data.get("username", "").strip().lower()
    password_hash = data.get("password_hash", "").strip()
    
    if not username or not password_hash:
        return jsonify({
            "success": False,
            "error": "Username y hash son requeridos"
        }), 400
        
    # Validación de formato MD5 (Defensa contra Inyección)
    if not re.match(r'^[a-fA-F0-9]{32}$', password_hash):
        return jsonify({
            "success": False,
            "error": "Formato de hash inválido. Se requiere MD5 (32 caracteres hexadecimales)."
        }), 400
    
    # Verificar si el usuario existe
    if username not in USERS_DB:
        # VULNERABILIDAD: Mensaje diferente para usuario no encontrado vs contraseña incorrecta
        # Esto permite enumerar usuarios
        return jsonify({
            "success": False,
            "error": f"Usuario '{username}' no encontrado"  # USER ENUMERATION VULNERABILITY
        }), 404
    
    user = USERS_DB[username]
    stored_hash = user["password_hash"]
    
    print(f"  Hash almacenado: {stored_hash}")
    print(f"  ¿Coinciden?: {password_hash == stored_hash}")
    
    # VULNERABILIDAD PASS-THE-HASH:
    # Comparación directa de hashes sin verificar la contraseña original
    if password_hash == stored_hash:
        # Login exitoso
        session["username"] = username
        session["role"] = user["role"]
        
        return jsonify({
            "success": True,
            "message": f"¡Bienvenido, {username}!",
            "role": user["role"],
            "redirect": "/dashboard",
            # VULNERABILIDAD: Devolvemos información sensible en la respuesta
            "debug_info": {
                "stored_hash": stored_hash,
                "received_hash": password_hash,
                "match": True
            }
        }), 200
    else:
        return jsonify({
            "success": False,
            "error": "Contraseña incorrecta (hash no coincide)",
            "debug_info": {
                "received_hash": password_hash,
                "expected_length": len(stored_hash),
                "algorithm": "MD5"  # VULNERABILIDAD: revelamos el algoritmo
            }
        }), 401


@app.route("/api/users", methods=["GET"])
def api_users():
    """
    VULNERABILIDAD CRÍTICA: Endpoint que expone todos los usuarios y sus hashes.
    En un sistema real esto NUNCA existiría.
    Para fines de laboratorio permite ver la "base de datos".
    """
    return jsonify({
        "note": "[EDUCATIVO] Endpoint inseguro - expone hashes de usuarios",
        "users": USERS_DB,
        "total": len(USERS_DB)
    })


@app.route("/api/hash", methods=["POST"])
def api_hash():
    """
    Utilidad: Genera hash MD5 de un texto (para demostración en laboratorio).
    """
    data = request.get_json()
    text = data.get("text", "")
    
    md5_hash = hashlib.md5(text.encode()).hexdigest()
    sha1_hash = hashlib.sha1(text.encode()).hexdigest()
    sha256_hash = hashlib.sha256(text.encode()).hexdigest()
    
    return jsonify({
        "input": text,
        "md5": md5_hash,
        "sha1": sha1_hash,
        "sha256": sha256_hash,
        "note": "MD5 y SHA1 son inseguros para almacenamiento de contraseñas"
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Cierra la sesión del usuario."""
    username = session.pop("username", None)
    session.pop("role", None)
    return jsonify({
        "success": True,
        "message": f"Sesión de '{username}' cerrada"
    })


# ============================================================
# INICIAR SERVIDOR
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  LAB3 CRIPTO - Servidor Flask Educativo")
    print("=" * 60)
    print("  ADVERTENCIA: Servidor INTENCIONALMENTE INSEGURO")
    print("  Solo usar en laboratorio controlado")
    print("=" * 60)
    print(f"  Usuarios pre-cargados:")
    for u, data in USERS_DB.items():
        print(f"    - {u}: hash={data['password_hash']}")
    print("=" * 60)
    print("  URL: http://127.0.0.1:5000")
    print("  Para Burp Suite: Configurar proxy en 127.0.0.1:8080")
    print("=" * 60)
    
    # debug=True para mostrar errores detallados (inseguro en producción)
    app.run(debug=True, host="0.0.0.0", port=5000)
