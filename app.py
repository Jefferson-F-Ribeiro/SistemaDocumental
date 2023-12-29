import datetime
import io
import hashlib
import os
import tempfile
import time
from datetime import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, render_template, redirect, url_for, flash, send_file, abort, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
import OpenSSL
from reportlab.pdfgen import canvas
from wtforms import StringField, PasswordField, SubmitField, validators

from forms import *
from models import db, User, PdfModel, SignedPdf

import OpenSSL
import os
import time
from apryse_sdk import *
from typing import Tuple
import PyPDF2
from OpenSSL.crypto import FILETYPE_PEM
from werkzeug.utils import secure_filename
import OpenSSL.crypto
from cryptography import x509
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto
import PyPDF4
from PyPDF4 import PdfFileReader, PdfFileWriter

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

def createKeyPair(type, bits):
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey

def create_self_signed_cert(pKey, name):
    """Create a self signed certificate. This certificate will not require to be signed by a Certificate Authority."""
    # Create a self signed certificate
    cert = OpenSSL.crypto.X509()
    # Common Name (e.g. server FQDN or Your Name)
    cert.get_subject().CN = name
    # Serial Number
    cert.set_serial_number(int(time.time() * 10))
    # Not Before
    cert.gmtime_adj_notBefore(0)  # Not before
    # Not After (Expire after 10 years)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    # Identify issue
    cert.set_issuer((cert.get_subject()))
    cert.set_pubkey(pKey)
    cert.sign(pKey, 'md5')  # or cert.sign(pKey, 'sha256')
    return cert

def load(name):
    """Generate the certificate"""
    summary = {}
    summary['OpenSSL Version'] = OpenSSL.__version__
    # Generating a Private Key...
    key = createKeyPair(OpenSSL.crypto.TYPE_RSA, 1024)
    # PEM encoded
    with open("static/private_key.pem", "wb") as pk:
        pk_str = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        pk.write(pk_str)
        summary['Private Key'] = pk_str
    # Done - Generating a private key...
    # Generating a self-signed client certification...
    cert = create_self_signed_cert(pKey=key, name=name)
    with open("static/certificate.cer", "wb") as cer:
        cer_str = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert)
        cer.write(cer_str)
        summary['Self Signed Certificate'] = cer_str
    # Done - Generating a self-signed client certification...
    # Generating the public key...
    with open("static/public_key.pem", "wb") as pub_key:
        pub_key_str = OpenSSL.crypto.dump_publickey(
            OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey())
        #print("Public key = ",pub_key_str)
        pub_key.write(pub_key_str)
        summary['Public Key'] = pub_key_str
    # Done - Generating the public key...
    # Take a private key and a certificate and combine them into a PKCS12 file.
    # Generating a container file of the private key and the certificate...
    p12 = OpenSSL.crypto.PKCS12()
    p12.set_privatekey(key)
    p12.set_certificate(cert)
    open("static/container.pfx", "wb").write(p12.export())
    # You may convert a PKSC12 file (.pfx) to a PEM format
    # Done - Generating a container file of the private key and the certificate...
    # To Display A Summary
    print("## Initialization Summary ##################################################")
    print("\n".join("{}:{}".format(i, j) for i, j in summary.items()))
    print("############################################################################")
    return True

from PDFNetPython import *

def sign_file(input_file: str, signatureID: str, x_coordinate: int, 
            y_coordinate: int, pages: Tuple = None, output_file: str = None
              ):
    try:
              
        """Sign a PDF file"""
        # An output file is automatically generated with the word signed added at its end
        if not output_file:
            output_file = (os.path.splitext(input_file)[0]) + "_signed.pdf"
        # Initialize the library
        PDFNet.Initialize("demo:1703829513035:7c8233b40300000000309845ad0e1c0bf5644ae6ae34825a17581d67f0")
        doc = PDFDoc(input_file)
        # Create a signature field
        sigField = SignatureWidget.Create(doc, Rect(x_coordinate, y_coordinate, x_coordinate+100, y_coordinate+50), signatureID)
        # Iterate throughout document pages
        for page in range(1, (doc.GetPageCount() + 1)):
            # If required for specific pages
            if pages:
                if str(page) not in pages:
                    continue
            pg = doc.GetPage(page)
            # Create a signature text field and push it on the page
            pg.AnnotPushBack(sigField)
        # Signature image
        #sign_filename = os.path.dirname(
         #      os.path.abspath(__file__)) + "/static/signature.jpg"
        # Self signed certificate
        pk_filename = os.path.dirname(
            os.path.abspath(__file__)) + "/static/container.pfx"
        # Retrieve the signature field.
        approval_field = doc.GetField(signatureID)
        approval_signature_digsig_field = DigitalSignatureField(approval_field)
        # Add appearance to the signature field.
        #img = Image.Create(doc.GetSDFDoc(), sign_filename)
        found_approval_signature_widget = SignatureWidget(approval_field.GetSDFObj())
       # found_approval_signature_widget.CreateSignatureAppearance(img)
        # Prepare the signature and signature handler for signing.
        approval_signature_digsig_field.SignOnNextSave(pk_filename, '')
        # The signing will be done during the following incremental save operation.
        doc.Save(output_file, SDFDoc.e_incremental)
        # Develop a Process Summary
        summary = {
            "Input File": input_file, 
            "Signature ID": signatureID, 
            "Output File": output_file, 
            "Certificate File": pk_filename
        }

        # Printing Summary
        print("## Summary ########################################################")
        print("\n".join("{}:{}".format(i, j) for i, j in summary.items()))
        print("###################################################################")
        print("PDF assinado com sucesso!")
     
    except Exception as e:
        print("Erro ao assinar o PDF:", e)
    
    return output_file

@app.route('/sign_pdf', methods=['GET', 'POST'])
@login_required
def sign_pdf():
    if request.method == "GET":
        return render_template("sign_pdf.html")

    if request.method == "POST":
        # Obter o PDF do usuário
        file = request.files["pdf"]
        if file.filename == "":
            return render_template("sign_pdf.html", error="Você precisa selecionar um PDF para assinar.")

        # Salvar o PDF em um local definitivo
        output_pdf = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(output_pdf)  # Salva o arquivo original diretamente no local definitivo

        # Obter o nome do certificado
        name = request.form["name"]

        load(name)

        

        # Assinar o PDF

        return send_file(sign_file(output_pdf,str(generate_key_hash(name)),300,100), as_attachment=True) # Envia o arquivo assinado como download
    
def is_pdf_signed(pdf_path):
    try:
        #pdf_document = fitz.open(pdf_path)

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