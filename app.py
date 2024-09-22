from flask import Flask, request, jsonify, send_file, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import os
import base64
import io

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)

class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)
    is_file = db.Column(db.Boolean, default=False)

def generate_key(password):
    return base64.urlsafe_b64encode(password.encode().ljust(32)[:32])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_text():
    title = request.form['title']
    password = request.form['password']
    plaintext = request.form['plaintext']
    
    key = generate_key(password)
    f = Fernet(key)
    encrypted_content = f.encrypt(plaintext.encode())
    
    new_secret = Secret(title=title, encrypted_content=encrypted_content, is_file=False)
    db.session.add(new_secret)
    db.session.commit()
    
    return jsonify({"message": "Text encrypted and saved successfully"})

@app.route('/encrypt-file', methods=['POST'])
def encrypt_file():
    file = request.files['file']
    title = request.form['fileTitle']
    secret_id = request.form['secretSelector']
    
    secret = Secret.query.get(secret_id)
    if not secret:
        return jsonify({"error": "Secret not found"}), 404
    
    key = generate_key(secret.encrypted_content[:32].decode())
    f = Fernet(key)
    
    encrypted_content = f.encrypt(file.read())
    
    new_secret = Secret(title=title, encrypted_content=encrypted_content, is_file=True)
    db.session.add(new_secret)
    db.session.commit()
    
    return send_file(
        io.BytesIO(encrypted_content),
        as_attachment=True,
        download_name=f"encrypted_{secure_filename(file.filename)}",
        mimetype="application/octet-stream"
    )

@app.route('/decrypt-file', methods=['POST'])
def decrypt_file():
    file = request.files['encryptedFile']
    secret_id = request.form['decryptSecretSelector']
    
    secret = Secret.query.get(secret_id)
    if not secret:
        return jsonify({"error": "Secret not found"}), 404
    
    key = generate_key(secret.encrypted_content[:32].decode())
    f = Fernet(key)
    
    try:
        decrypted_content = f.decrypt(file.read())
        return send_file(
            io.BytesIO(decrypted_content),
            as_attachment=True,
            download_name=f"decrypted_{secure_filename(file.filename)}",
            mimetype="application/octet-stream"
        )
    except:
        return jsonify({"error": "Decryption failed"}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt_text():
    secret_id = request.json['id']
    password = request.json['password']
    
    secret = Secret.query.get(secret_id)
    if not secret:
        return jsonify({"error": "Secret not found"}), 404
    
    key = generate_key(password)
    f = Fernet(key)
    
    try:
        decrypted_content = f.decrypt(secret.encrypted_content).decode()
        return jsonify({"decrypted_content": decrypted_content})
    except:
        return jsonify({"error": "Decryption failed"}), 400

@app.route('/secrets', methods=['GET'])
def get_secrets():
    secrets = Secret.query.all()
    return jsonify([{"id": s.id, "title": s.title, "is_file": s.is_file} for s in secrets])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)