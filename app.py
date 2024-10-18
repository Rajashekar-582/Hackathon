from flask import Flask, request, render_template, send_file, jsonify
import pandas as pd
from cryptography.fernet import Fernet
import os
import re
import hashlib
import random
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

# Helper functions
def read_csv(file_path):
    df = pd.read_csv(file_path)
    header = df.columns.tolist()
    data = df.values.tolist()
    return header, data

def write_csv(file_path, header, data):
    df = pd.DataFrame(data, columns=header)
    df.to_csv(file_path, index=False)

def load_key_from_directory(key_file, key_directory):
    with open(os.path.join(key_directory, key_file), 'rb') as file:
        return file.read()

def load_token_map_from_directory(token_map_file, key_directory):
    with open(os.path.join(key_directory, token_map_file), 'r') as file:
        return eval(file.read())

# Tokenization using chaotic logic
def chaotic_tokenize_data(data, token_key):
    token_map = {}
    tokenized_data = []
    for item in data:
        chaotic_seed = hashlib.sha256(item.encode() + token_key).digest()
        chaotic_value = chaotic_key(chaotic_seed)
        token = hashlib.sha256(chaotic_value).hexdigest()
        token_map[token] = item
        tokenized_data.append(token)
    return tokenized_data, token_map

# Chaotic Key Generation (Logistic Map-based Chaos Function)
def chaotic_key(seed, iterations=1000):
    x = 0.5
    r = 3.9
    for _ in range(iterations):
        x = r * x * (1 - x)
    chaotic_value = int((x * 10**16) % 256)
    chaotic_value_bytes = chaotic_value.to_bytes((chaotic_value.bit_length() + 7) // 8, byteorder='big')
    random.seed(seed + chaotic_value_bytes)
    return os.urandom(32)

@app.route('/tokenize', methods=['POST'])
def tokenize():
    try:
        file = request.files['file']
        df = pd.read_csv(file)

        # Generate a key for tokenization
        token_key = os.urandom(32)

        # Save the tokenization key securely in a new directory
        token_key_dir = 'C:/Users/Administrator/Downloads/TokenKeys'
        if not os.path.exists(token_key_dir):
            os.makedirs(token_key_dir)
        token_key_path = os.path.join(token_key_dir, 'token.key')
        with open(token_key_path, 'wb') as key_file:
            key_file.write(token_key)

       

        # Convert all columns to string type for tokenization
        df = df.astype(str)

        # List of regex patterns to match sensitive columns
        patterns = [
           
            re.compile(r'aadhaar|aadhar', re.IGNORECASE),
            re.compile(r'pan', re.IGNORECASE)
        ]

        # Tokenize sensitive columns using chaotic logic
        token_map = {}
        for column in df.columns:
            if any(pattern.search(column) for pattern in patterns):
                tokenized_data, column_token_map = chaotic_tokenize_data(df[column], token_key)
                token_map.update(column_token_map)
                df[column] = tokenized_data

        # Save the token map to a specified directory
        token_map_dir = 'C:/Users/Administrator/Downloads/TokenMaps'
        if not os.path.exists(token_map_dir):
            os.makedirs(token_map_dir)
        token_map_path = os.path.join(token_map_dir, 'token_map.txt')
        with open(token_map_path, 'w') as token_map_file:
            token_map_file.write(str(token_map))

        # Save the tokenized DataFrame to a CSV file
        df.to_csv('tokenized.csv', index=False)

        return send_file('tokenized.csv',as_attachment=True) and render_template('/success.html')

    except Exception as e:
        return jsonify({"error": str(e)}) and render_template('/fail.html'), 500

@app.route('/encrypt_backup', methods=['POST'])
def encrypt_backup():
    try:
        file = request.files['file']
        file.save('temp_tokenized_file.csv')

         # Generate a key for encryption
        encryption_key = Fernet.generate_key()
        fernet = Fernet(encryption_key)

        # Save the encryption key securely in a new directory
        encryption_key_dir = 'C:/Users/Administrator/Downloads/SecretKeys'
        if not os.path.exists(encryption_key_dir):
            os.makedirs(encryption_key_dir)
        encryption_key_path = os.path.join(encryption_key_dir, 'encryption.key')
        with open(encryption_key_path, 'wb') as key_file:
            key_file.write(encryption_key)

        # Load the encryption key
        encryption_key_dir = 'C:/Users/Administrator/Downloads/SecretKeys'
        encryption_key_path = os.path.join(encryption_key_dir, 'encryption.key')
        with open(encryption_key_path, 'rb') as key_file:
            encryption_key = key_file.read()

        fernet = Fernet(encryption_key)

        with open('temp_tokenized_file.csv', 'rb') as file:
            original = file.read()

        encrypted = fernet.encrypt(original)
        encrypted_file_dir = 'C:/Users/Administrator/Downloads/EncryptedFiles'
        if not os.path.exists(encrypted_file_dir):
            os.makedirs(encrypted_file_dir)
        encrypted_file_path = os.path.join(encrypted_file_dir, 'encrypted_tokenized.csv')
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

        # Backup the encrypted file
        backup_dir = 'C:/Users/Administrator/Downloads/BackUp'
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        shutil.copy(encrypted_file_path, os.path.join(backup_dir, 'encrypted_tokenized_backup.csv'))

        os.remove('temp_tokenized_file.csv')

        return "Backup  encrypted successfully"  and render_template('/encrypt.html')


    except Exception as e:
        return jsonify({"error": str(e)})  and render_template('/fail.html'), 500

@app.route('/decrypt_recover', methods=['POST'])
def decrypt_recover():
    try:
        file = request.files['file']
        file.save('temp_encrypted_file.csv')

        # Load the encryption key
        encryption_key_dir = 'C:/Users/Administrator/Downloads/SecretKeys'
        encryption_key_path = os.path.join(encryption_key_dir, 'encryption.key')
        with open(encryption_key_path, 'rb') as key_file:
            encryption_key = key_file.read()

        fernet = Fernet(encryption_key)

        with open('temp_encrypted_file.csv', 'rb') as enc_file:
            encrypted = enc_file.read()

        decrypted = fernet.decrypt(encrypted)
        decrypted_file_dir = 'C:/Users/Administrator/Downloads/DecryptedFiles'
        if not os.path.exists(decrypted_file_dir):
            os.makedirs(decrypted_file_dir)
        recovered_file = os.path.join(decrypted_file_dir, 'decrypted_tokenized.csv')
        with open(recovered_file, 'wb') as dec_file:
            dec_file.write(decrypted)

        os.remove('temp_encrypted_file.csv')

        return send_file(recovered_file,as_attachment=True) and render_template('/decrypt.html')

    except Exception as e:
        return jsonify({"error": str(e)})   and render_template('/fail.html'), 500

@app.route('/detokenize', methods=['POST'])
def detokenize():
    try:
        file = request.files['file']
        df = pd.read_csv(file)

        # Load the token map
        token_map_dir = 'C:/Users/Administrator/Downloads/TokenMaps'
        token_map_path = os.path.join(token_map_dir, 'token_map.txt')
        with open(token_map_path, 'r') as token_map_file:
            token_map = eval(token_map_file.read())

        # List of regex patterns to match sensitive columns
        patterns = [
            re.compile(r'aadhaar|aadhar', re.IGNORECASE),
            re.compile(r'pan', re.IGNORECASE)
        ]

        # Detokenize sensitive columns
        for column in df.columns:
            if any(pattern.search(column) for pattern in patterns):
                df[column] = df[column].apply(lambda x: token_map[x])

        output_file_path = 'detokenized.csv'
        df.to_csv(output_file_path, index=False)

        return send_file(output_file_path, as_attachment=True) and render_template('/detok.html')

    except Exception as e:
        return jsonify({"error": str(e)})   and render_template('/fail.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
