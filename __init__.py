from flask import Flask, request
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os

app = Flask(__name__)

# --- Helpers ---
def derive_fernet_key(passphrase: str, salt: bytes, iterations: int = 390000) -> bytes:
    """
    Dérive une clé 32-octets à partir d'une passphrase et d'un salt via PBKDF2-HMAC-SHA256,
    puis renvoie la clé encodée au format urlsafe_b64 attendu par Fernet.
    """
    if not passphrase or not isinstance(passphrase, str):
        raise ValueError("La passphrase doit être une chaîne non vide.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    return base64.urlsafe_b64encode(key)  # Fernet attend une clé urlsafe base64

def b64_encode(bytes_obj: bytes) -> str:
    return base64.urlsafe_b64encode(bytes_obj).decode('utf-8')

def b64_decode(str_obj: str) -> bytes:
    return base64.urlsafe_b64decode(str_obj.encode('utf-8'))


# --- Routes ---
# Exemple: /encrypt/Bonjour/maPassphrase  (penser à URL-encoder si nécessaire)
@app.route('/encrypt/<string:valeur>/<string:passphrase>')
def encryptage(valeur, passphrase):
    try:
        # Génération d'un salt unique par chiffrement (16 octets)
        salt = os.urandom(16)
        fernet_key = derive_fernet_key(passphrase, salt)  # bytes (base64 encodée)
        f = Fernet(fernet_key)

        valeur_bytes = valeur.encode('utf-8')
        token = f.encrypt(valeur_bytes)  # token bytes (Fernet format)

        # On renvoie salt + token, encodés en base64 urlsafe pour transporter facilement
        payload = salt + token
        payload_b64 = b64_encode(payload)
        return f"Valeur encryptée : {payload_b64}"
    except Exception as e:
        return f"Erreur lors du chiffrement : {str(e)}", 500


# Exemple: /decrypt/<payload_b64>/<passphrase>
# payload_b64 = la valeur retournée précédemment (salt+token encodés en base64 urlsafe)
@app.route('/decrypt/<string:payload_b64>/<string:passphrase>')
def decryptage(payload_b64, passphrase):
    try:
        payload = b64_decode(payload_b64)  # bytes : salt(16) + token
        if len(payload) <= 16:
            return "Payload invalide.", 400

        salt = payload[:16]
        token = payload[16:]  # reste = token Fernet

        fernet_key = derive_fernet_key(passphrase, salt)
        f = Fernet(fernet_key)

        plaintext_bytes = f.decrypt(token)  # lève InvalidToken si passephrase erronée / token altéré
        return f"Valeur decryptée : {plaintext_bytes.decode('utf-8')}"
    except InvalidToken:
        return "Erreur : token invalide ou passphrase incorrecte.", 400
    except Exception as e:
        return f"Erreur serveur lors du décryptage : {str(e)}", 500


if __name__ == "__main__":
    app.run(debug=True)
