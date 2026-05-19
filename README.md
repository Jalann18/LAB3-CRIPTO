# LAB3 CRIPTO - Laboratorio de Hashing y Auth Bypass (Pass-the-Hash)

> ADVERTENCIA: Sitio INTENCIONALMENTE VULNERABLE. Solo uso educativo.

## Inicio Rapido

`ash
pip install flask
python app.py
# Abrir http://127.0.0.1:5000
`

## Credenciales de Prueba
| Usuario | Contrasena  | Hash MD5                         |
|---------|-------------|----------------------------------|
| admin   | password123 | 482c811da5d5b4bc6d497ffa98491e38 |
| alice   | alice2024   | ver /api/users                   |

## Demostrar Reutilización de Hash (Pass-the-Hash) con Burp Suite
1. Burp Proxy en 127.0.0.1:8080
2. Ir a /login, escribir usuario admin, contrasena INCORRECTA
3. Interceptar en Burp Suite
4. Modificar password_hash a: 482c811da5d5b4bc6d497ffa98491e38
5. Forward -> Login exitoso sin conocer la contrasena! (Auth Bypass)

## Por que MD5 es Inseguro
- GPU: 10 billones de MD5/segundo
- Sin salt: rainbow tables funcionan
- Colisiones conocidas desde 2004
- Hash en cliente = hash ES la contrasena

## Solucion Correcta
Usar bcrypt/Argon2 en servidor con salt automatico.

## Endpoints API
| Metodo | Ruta         | Descripcion               |
|--------|--------------|---------------------------|
| POST   | /api/login   | Login (Pass-the-Hash)     |
| POST   | /api/register| Registrar usuario         |
| GET    | /api/users   | INSEGURO - expone hashes  |
| POST   | /api/hash    | Calcular hashes           |
| GET    | /policies    | Politicas corporativas    |

---
Laboratorio educativo de Ciberseguridad
