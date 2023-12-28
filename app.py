import io
import hashlib
import os
import tempfile
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, render_template, redirect, url_for, flash, send_file, abort, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from OpenSSL import crypto
from reportlab.pdfgen import canvas
from wtforms import StringField, PasswordField, SubmitField, validators

from forms import *
from models import db, User, PdfModel


app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'chave_secreta_super_secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

ALLOWED_EXTENSIONS = {'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(key_hash.encode('utf-8'))

    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(content.encode('utf-8')) + encryptor.finalize()

    return salt + iv + ciphertext

def decrypt_content(ciphertext, key_hash):
    salt = ciphertext[:16]
    iv = ciphertext[16:32]
    content_ciphertext = ciphertext[32:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(key_hash.encode('utf-8'))

    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

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

        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_file.filename)
        pdf_file.save(pdf_path)

        output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'signed_' + pdf_file.filename)

        apply_digital_signature(pdf_path, output_path, signature_id, name, reason, location)

        os.remove(pdf_path)

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
    cert.sign(pKey, 'sha256')
    return cert

def apply_digital_signature(input_path, output_path, signature_id, name, reason="Testing", location="City"):
    pdf_document = fitz.open(input_path)

    pkey = createKeyPair(crypto.TYPE_RSA, 2048)
    cert = create_self_signed_cert(pkey, name)

    certificate_path = "temp_certificate.pem"
    private_key_path = "temp_private_key.pem"

    with open(certificate_path, "wb") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open(private_key_path, "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))

    with open(certificate_path, "rb") as cert_file:
        certificate_data = cert_file.read()

    with open(private_key_path, "rb") as key_file:
        private_key_data = key_file.read()

    for page_number in range(pdf_document.page_count):
        page = pdf_document[page_number]

        point = fitz.Point(100, 100)

        page.insert_text(point, f"Signed by: {name}")

    pdf_document.save(output_path)

    os.remove(certificate_path)
    os.remove(private_key_path)

def is_pdf_signed(pdf_path):
    try:
        pdf_document = fitz.open(pdf_path)

        for page_number in range(pdf_document.page_count):
            page = pdf_document[page_number]

            annotations = page.get_text("text", clip=page.rect)

            if "Signed by:" in annotations:
                return True

        return False

    except Exception as e:
        print(f"Error checking digital signature: {e}")
        return False

@app.route('/check_pdf_signature', methods=['POST'])
def check_pdf_signature():
    if 'pdf_file' not in request.files:
        return "No PDF file uploaded", 400

    pdf_file = request.files['pdf_file']

    if pdf_file.filename == '':
        return "No selected file", 400

    if pdf_file and allowed_file(pdf_file.filename):
        temp_pdf_path = os.path.join(tempfile.gettempdir(), pdf_file.filename)
        pdf_file.save(temp_pdf_path)

        if is_pdf_signed(temp_pdf_path):
            return "O PDF possui assinatura digital"
        else:
            return "O PDF nao possui assinatura digital"

    return "Invalid file format", 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)