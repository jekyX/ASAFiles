from flask import Flask, request, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from datetime import datetime
import os

# Membuat instance Flask
app = Flask(__name__)
app.secret_key = "your_secret_key_here"

# Konfigurasi folder untuk upload, file terenkripsi, dan file terdekripsi
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ENCRYPTED_FOLDER'] = 'encrypted_files'
app.config['DECRYPTED_FOLDER'] = 'decrypted_files'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ENCRYPTED_FOLDER'], exist_ok=True)
os.makedirs(app.config['DECRYPTED_FOLDER'], exist_ok=True)

# Generate RSA key pair (disimpan untuk digunakan)
rsa_key = RSA.generate(2048)
private_key = rsa_key.export_key()
public_key = rsa_key.publickey().export_key()
with open("private.pem", "wb") as f:
    f.write(private_key)
with open("public.pem", "wb") as f:
    f.write(public_key)

# Simpan metadata di memori (dictionary)
metadata_store = {}

def encrypt_file(file_path, output_path, password):
    # Generate AES key dari password
    salt = get_random_bytes(16)
    aes_key = PBKDF2(password, salt, dkLen=16)

    # Enkripsi file
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    with open(file_path, 'rb') as f:
        file_data = f.read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)

    # Simpan file terenkripsi
    with open(output_path, 'wb') as f:
        original_name = os.path.basename(file_path).encode()
        f.write(len(original_name).to_bytes(2, 'big'))  # Panjang nama file asli
        f.write(original_name)  # Nama file asli
        f.write(salt)  # Salt
        f.write(cipher_aes.nonce)  # Nonce
        f.write(tag)  # Tag
        f.write(ciphertext)  # Ciphertext


def decrypt_file(file_path, output_folder, password):
    with open(file_path, 'rb') as f:
        name_length = int.from_bytes(f.read(2), 'big')
        original_name = f.read(name_length).decode()
        salt = f.read(16)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    # Generate kembali AES key dari password
    aes_key = PBKDF2(password, salt, dkLen=16)

    # Dekripsi file
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    file_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Simpan hasil dekripsi
    output_path = os.path.join(output_folder, original_name)
    with open(output_path, 'wb') as f:
        f.write(file_data)

    return output_path


def encrypt_file_hybrid(file_path, output_path, password):
    """Metode hybrid: Enkripsi file dengan AES, lalu kunci AES dengan RSA."""
    # Generate AES key dari password
    salt = get_random_bytes(16)
    aes_key = PBKDF2(password, salt, dkLen=16)

    # Enkripsi file dengan AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    with open(file_path, 'rb') as f:
        file_data = f.read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)

    # Enkripsi kunci AES dengan RSA
    with open("public.pem", "rb") as f:
        rsa_public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Simpan file terenkripsi dengan metadata
    with open(output_path, 'wb') as f:
        original_name = os.path.basename(file_path).encode()
        f.write(len(original_name).to_bytes(2, 'big'))  # Panjang nama file asli
        f.write(original_name)  # Nama file asli
        f.write(salt)  # Salt
        f.write(cipher_aes.nonce)  # Nonce
        f.write(tag)  # Tag
        f.write(len(encrypted_aes_key).to_bytes(2, 'big'))  # Panjang kunci AES terenkripsi
        f.write(encrypted_aes_key)  # Kunci AES terenkripsi
        f.write(ciphertext)  # Ciphertext



def decrypt_file_hybrid(file_path, output_folder, private_key_path):
    with open(file_path, 'rb') as f:
        name_length = int.from_bytes(f.read(2), 'big')
        original_name = f.read(name_length).decode()
        salt = f.read(16)
        nonce = f.read(16)
        tag = f.read(16)
        key_length = int.from_bytes(f.read(2), 'big')
        encrypted_aes_key = f.read(key_length)
        ciphertext = f.read()

    # Dekripsi kunci AES dengan RSA
    with open(private_key_path, 'rb') as f:
        rsa_private_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Dekripsi file dengan AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    file_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Simpan hasil dekripsi
    output_path = os.path.join(output_folder, original_name)
    with open(output_path, 'wb') as f:
        f.write(file_data)

    return output_path



@app.route('/')
def home():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    uploaded_file = request.files['file']
    password = request.form['password']
    method = request.form['method']  # AES atau Hybrid

    if uploaded_file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
        uploaded_file.save(file_path)

        base_name = os.path.splitext(uploaded_file.filename)[0]
        output_filename = f'{base_name}_encrypted.txt'
        output_path = os.path.join(app.config['ENCRYPTED_FOLDER'], output_filename)
        
        # Catat waktu mulai enkripsi
        start_time = datetime.now()

        if method == 'AES':
            encrypt_file(file_path, output_path, password)
        elif method == 'Hybrid':
            encrypt_file_hybrid(file_path, output_path, password)

         # Catat waktu selesai enkripsi
        end_time = datetime.now()
        encryption_time = (end_time - start_time).total_seconds()  # Dalam detik

        # Simpan metadata ke dictionary
        metadata_store[output_filename] = {
            'method': method,
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'encryption_time': f"{encryption_time:.2f} seconds",
            'decryption_time': 'Not yet decrypted'
        }

        return redirect(url_for('list_encrypted_files'))

    return "File tidak ditemukan. Silakan unggah file."

@app.route('/encrypted_files')
def list_encrypted_files():
    files = os.listdir(app.config['ENCRYPTED_FOLDER'])
    file_list = []
    for idx, file_name in enumerate(files):
        if file_name.endswith('.meta'):  # Lewati file metadata
            continue

        file_path = os.path.join(app.config['ENCRYPTED_FOLDER'], file_name)
        file_size = os.path.getsize(file_path)

        # Ambil metadata dari dictionary
        metadata = metadata_store.get(file_name, {'method': 'Unknown', 'date': 'Unknown'})


        # Tambahkan ke daftar file
        file_list.append({
            'no': idx + 1,
            'source_name': file_name.replace('.txt', ''),
            'encrypted_name': file_name,
            'path': file_path,
            'size': f'{file_size} bytes',
            'status': 'Encrypted',
            'encryption_date': metadata['date'],
            'encryption_method': metadata['method'],
            'encryption_time': metadata.get('encryption_time', 'N/A'),  # Tambahkan waktu enkripsi
            'decryption_time': metadata.get('decryption_time', 'N/A')   # Tambahkan waktu dekripsi
        })

    return render_template('hasil_enkrip.html', files=file_list)


@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        encrypted_file = request.form['file_name']
        password = request.form.get('password')  # Hanya untuk metode AES
        private_key_file = request.files.get('private_key')  # Untuk Hybrid

        if encrypted_file:
            file_path = os.path.join(app.config['ENCRYPTED_FOLDER'], encrypted_file)
            try:

                # Catat waktu mulai dekripsi
                start_time = datetime.now()

                # Jika private key diunggah, artinya ini adalah dekripsi Hybrid
                if private_key_file:  # Hybrid decryption
                    private_key_file.save("temp_private.pem")  # Simpan sementara private key
                    output_path = decrypt_file_hybrid(file_path, app.config['DECRYPTED_FOLDER'], "temp_private.pem")
                else:  # AES decryption
                    output_path = decrypt_file(file_path, app.config['DECRYPTED_FOLDER'], password)

                 # Catat waktu selesai dekripsi
                end_time = datetime.now()
                decryption_time = (end_time - start_time).total_seconds()  # Dalam detik

                # Perbarui metadata dengan waktu dekripsi
                if encrypted_file in metadata_store:
                    metadata_store[encrypted_file]['decryption_time'] = f"{decryption_time:.2f} seconds"

                flash(f"File berhasil didekripsi dan disimpan sebagai {output_path}", "success")
                return redirect(url_for('decrypt'))
            except Exception as e:
                flash(f"Kesalahan selama proses dekripsi: {e}", "error")
                return redirect(url_for('decrypt'))

        flash("File tidak ditemukan. Silakan pilih file untuk didekripsi.", "error")
        return redirect(url_for('decrypt'))

        return "File tidak ditemukan. Silakan pilih file untuk didekripsi."

    # Menampilkan daftar file terenkripsi
    files = os.listdir(app.config['ENCRYPTED_FOLDER'])
    file_list = [{'encrypted_name': file_name} for file_name in files]
    return render_template('dekrip_file.html', files=file_list)

if __name__ == '__main__':
    app.run(debug=True)
