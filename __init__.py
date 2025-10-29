from cryptography.fernet import Fernet
from flask import Flask, render_template_string, render_template, jsonify
from flask import render_template
from flask import json
from urllib.request import urlopen
import sqlite3
                                                                                                                                       
app = Flask(_name_)                                                                                                                  
                                                                                                                                       
@app.route('/')
def hello_world():
    return render_template('hello.html') #Comm2

key = Fernet.generate_key()
f = Fernet(key)

@app.route('/encrypt/<string:valeur>')
def encryptage(valeur):
    valeur_bytes = valeur.encode()  # Conversion str -> bytes
    token = f.encrypt(valeur_bytes)  # Encrypt la valeur
    return f"Valeur encryptée : {token.decode()}"  # Retourne le token en str
                                                                                                                                                     
if _name_ == "_main_":
  app.run(debug=True)
@app.route('/decrypt/<string:token>')
def decryptage(token):
    """
    Inverse de la route encrypt.
    URL attendue : /decrypt/<le_token_recu>
    Retourne la valeur décryptée ou un message d'erreur si la clé/token sont invalides.
    """
    try:
        token_bytes = token.encode()            # token (str) -> bytes
        plaintext_bytes = f.decrypt(token_bytes)  # déchiffre (lève InvalidToken si échec)
        return f"Valeur decryptée : {plaintext_bytes.decode()}"
    except InvalidToken:
        return "Erreur : token invalide ou clé incorrecte.", 400
    except Exception as e:
        return f"Erreur serveur lors du décryptage : {str(e)}", 500

if _name_ == "_main_":
    app.run(debug=True)
