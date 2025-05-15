from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import hashlib

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    return data[:-data[-1]]

def derive_key(password, key_size):
    return hashlib.sha256(password.encode()).digest()[:key_size // 8]

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        password = request.form['password']
        key_size = int(request.form['key_size'])
        action = request.form['action']
        key = derive_key(password, key_size)

        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        with open(filepath, 'rb') as f:
            data = f.read()

        if action == 'encrypt':
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = iv + cipher.encrypt(pad(data))
            output_path = os.path.join(OUTPUT_FOLDER, 'encrypted_' + file.filename)
        else:
            iv = data[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = unpad(cipher.decrypt(data[16:]))
            output_path = os.path.join(OUTPUT_FOLDER, 'decrypted_' + file.filename)

        with open(output_path, 'wb') as f:
            f.write(ciphertext)

        return send_file(output_path, as_attachment=True)

    return render_template('index.html')
if __name__ == '__main__':
    app.run(debug=True)
