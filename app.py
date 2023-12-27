from flask import Flask, render_template, redirect, url_for, flash, send_file, abort
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, PdfModel
from forms import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import io
from reportlab.pdfgen import canvas
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from OpenSSL import crypto
import time
import os
import fitz

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'chave_secreta_super_secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    name = StringField('Nome', [validators.Length(min=1, max=50)])
    username = StringField('Nome de Usuário', [validators.Length(min=4, max=25)])
    password = PasswordField('Senha', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='As senhas devem coincidir')
    ])
    confirm = PasswordField('Repita a Senha')
    submit = SubmitField('Cadastrar')

class LoginForm(FlaskForm):
    username = StringField('Nome de Usuário')
    password = PasswordField('Senha')
    submit = SubmitField('Login')

def generate_key_hash(key):
    return hashlib.md5(key.encode('utf-8')).hexdigest()

def encrypt_content(content, key_hash):
    # Derivar a chave usando PBKDF2 com SHA-256
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Comprimento da chave em bytes
        salt=salt,
        iterations=100000,  # Ajuste conforme necessário
        backend=default_backend()
    )
    derived_key = kdf.derive(key_hash.encode('utf-8'))

    # Gerar um IV (vetor de inicialização) aleatório
    iv = os.urandom(16)

    # Criar o objeto Cipher
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Criptografar o conteúdo
    ciphertext = encryptor.update(content.encode('utf-8')) + encryptor.finalize()

    # Retornar IV e texto cifrado (e.g., para armazenar no banco de dados)
    return salt + iv + ciphertext

def decrypt_content(ciphertext, key_hash):
    # Extrair o salt, IV e conteúdo cifrado
    salt = ciphertext[:16]
    iv = ciphertext[16:32]
    content_ciphertext = ciphertext[32:]

    # Derivar a chave usando PBKDF2 com SHA-256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(key_hash.encode('utf-8'))

    # Criar o objeto Cipher
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Descriptografar o conteúdo
    decrypted_content = decryptor.update(content_ciphertext) + decryptor.finalize()

    return decrypted_content.decode('utf-8')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        key_hash = generate_key_hash(form.username.data)

        new_user = User(
            name=form.name.data,
            username=form.username.data,
            password=form.password.data,
            key_hash=key_hash
        )

        db.session.add(new_user)
        db.session.commit()
        flash('Cadastro realizado com sucesso!', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data, password=form.password.data).first()

        if user:
            login_user(user)
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Nome de usuário ou senha incorretos. Tente novamente.', 'danger')
    return render_template('login.html', form=form)

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    pdfs = PdfModel.query.filter_by(user_id=current_user.id).all()
    form = PdfForm()

    if form.validate_on_submit():
        pdf_content = form.content.data
        encrypted_content = encrypt_content(pdf_content, current_user.key_hash)

        new_pdf = PdfModel(content=encrypted_content, user_id=current_user.id)
        db.session.add(new_pdf)
        db.session.commit()

        # Iprime o conteúdo encriptado no console
        print(f'Encrypted PDF Content: {encrypted_content}')

        flash('PDF salvo com sucesso!', 'success')
        return redirect(url_for('home'))

    return render_template('home.html', form=form, pdfs=pdfs)

@app.route('/edit_pdf/<int:pdf_id>', methods=['GET', 'POST'])
@login_required
def edit_pdf(pdf_id):
    pdf = PdfModel.query.get_or_404(pdf_id)
    form = PdfForm()

    if form.validate_on_submit():
        pdf.content = encrypt_content(form.content.data, current_user.key_hash)
        db.session.commit()
        flash('PDF editado com sucesso!', 'success')
        return redirect(url_for('home'))

    return render_template('edit_pdf.html', form=form, pdf=pdf)

@app.route('/download_pdf/<int:pdf_id>')
@login_required
def download_pdf(pdf_id):
    pdf = PdfModel.query.get_or_404(pdf_id)
    decrypted_content = decrypt_content(pdf.content, current_user.key_hash)

    # Iprime o conteúdo desencriptado no console
    print(f'Decrypted PDF Content: {decrypted_content}')

    buffer = io.BytesIO()

    p = canvas.Canvas(buffer)
    p.drawString(100, 100, decrypted_content)
    p.save()

    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name=f'pdf_{pdf.id}.pdf', mimetype='application/pdf')


@app.route('/delete_pdf/<int:pdf_id>', methods=['POST'])
@login_required
def delete_pdf(pdf_id):
    pdf = PdfModel.query.get_or_404(pdf_id)

    if pdf.user_id != current_user.id:
        abort(403)

    db.session.delete(pdf)
    db.session.commit()
    flash('PDF deletado com sucesso!', 'success')
    return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('index'))

@app.route('/sign_pdf', methods=['GET', 'POST'])
@login_required
def sign_pdf():
    form = SignatureForm()

    if form.validate_on_submit():
        pdf_file = form.pdf_file.data
        signature_id = form.signature_id.data
        name = form.name.data
        reason = form.reason.data
        location = form.location.data

        # Save the uploaded PDF temporarily
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_file.filename)
        pdf_file.save(pdf_path)

        # Create a temporary output file path
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'signed_' + pdf_file.filename)

        # Apply digital signature
        apply_digital_signature(pdf_path, output_path, signature_id, name, reason, location)

        # Clean up: Remove the temporary uploaded PDF
        os.remove(pdf_path)

        # Provide the signed PDF for download
        return send_file(output_path, as_attachment=True, download_name='signed_pdf.pdf')

    return render_template('sign_pdf.html', form=form)

def createKeyPair(type, bits):
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey

def create_self_signed_cert(pKey, name):
    cert = crypto.X509()
    cert.get_subject().CN = name
    cert.set_serial_number(int(time.time() * 10))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(pKey)
    cert.sign(pKey, 'sha256')  # Use 'sha256' instead of 'md5'
    return cert

def apply_digital_signature(input_path, output_path, signature_id, name, reason="Testing", location="City"):
    pdf_document = fitz.open(input_path)

    # Generate key pair and self-signed certificate
    pkey = createKeyPair(crypto.TYPE_RSA, 2048)
    cert = create_self_signed_cert(pkey, name)

    # Save the certificate and private key to temporary files
    certificate_path = "temp_certificate.pem"
    private_key_path = "temp_private_key.pem"

    with open(certificate_path, "wb") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open(private_key_path, "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))

    # Load the certificate and private key from temporary files
    with open(certificate_path, "rb") as cert_file:
        certificate_data = cert_file.read()

    with open(private_key_path, "rb") as key_file:
        private_key_data = key_file.read()

    # Apply the digital signature to each page
    for page_number in range(pdf_document.page_count):
        page = pdf_document[page_number]

        # Coordinates for the signature
        point = fitz.Point(100, 100)

        # Insert the digital signature into the PDF
        page.insert_text(point, f"Signed by: {name}")

    # Save the modified PDF
    pdf_document.save(output_path)

    # Clean up: Remove temporary files
    os.remove(certificate_path)
    os.remove(private_key_path)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)