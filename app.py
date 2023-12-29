import io
import hashlib
import os
import time
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, render_template, redirect, url_for, flash, send_file, abort, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from reportlab.pdfgen import canvas
from wtforms import StringField, PasswordField, SubmitField, validators
from models import db, User, PdfModel, SignedPdf
import OpenSSL
from apryse_sdk import *
from typing import Tuple
from PDFNetPython import *


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

def adicionar_entrada_log(mensagem):
    try:
        with open('app.log', 'a') as log_file:
            if not os.path.exists('app.log'):
                log_file.write("Log file created on: {}\n".format(datetime.now()))
            log_file.write("[{}] {}\n".format(datetime.now(), mensagem))
    except Exception as e:
        print(e)

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
    create_admin()
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            key_hash = generate_key_hash(form.username.data)

            new_user = User(
                name=form.name.data,
                username=form.username.data,
                password=form.password.data,
                key_hash=key_hash,
                admin=False
            )

            db.session.add(new_user)
            db.session.commit()
            flash('Cadastro realizado com sucesso!', 'success')
            log_message = f'Um usuário chamado {form.name.data} foi cadastrado.'
            adicionar_entrada_log(log_message)
            return redirect(url_for('index'))
        
        except Exception as e:
            print(e)

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data, password=form.password.data).first()

        if user:
            login_user(user)
            if (user.admin == False):
                flash('Login bem-sucedido!', 'success')
                log_message = f'O usuário chamado {user.username} logou no sistema.'
                adicionar_entrada_log(log_message)
                return redirect(url_for('home'))
            elif (user.admin):
                flash('Login bem-sucedido!', 'success')
                log_message = f'O Administrador {user.username} logou no sistema.'
                adicionar_entrada_log(log_message)
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
        log_message = f'O usuário chamado {current_user.username} criou um PDF.'
        adicionar_entrada_log(log_message)
        flash('PDF salvo com sucesso!', 'success')
        return redirect(url_for('home'))

    return render_template('home.html', form=form, pdfs=pdfs)

@app.route('/download_log', methods=['GET'])
@login_required
def download_log():
    if not current_user.admin:
        abort(403)

    log_path = 'app.log'
    return send_file(log_path, as_attachment=True)

@app.route('/edit_pdf/<int:pdf_id>', methods=['GET', 'POST'])
@login_required
def edit_pdf(pdf_id):
    pdf = PdfModel.query.get_or_404(pdf_id)
    form = PdfForm()

    if form.validate_on_submit():
        pdf.content = encrypt_content(form.content.data, current_user.key_hash)
        db.session.commit()
        log_message = f'O usuário chamado {current_user.username} editou o PDF {pdf_id}.'
        adicionar_entrada_log(log_message)
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

    log_message = f'O usuário chamado {current_user.username} baixou o PDF {pdf_id}.'
    adicionar_entrada_log(log_message)

    return send_file(buffer, as_attachment=True, download_name=f'pdf_{pdf.id}.pdf', mimetype='application/pdf')


@app.route('/delete_pdf/<int:pdf_id>', methods=['POST'])
@login_required
def delete_pdf(pdf_id):
    pdf = PdfModel.query.get_or_404(pdf_id)

    if pdf.user_id != current_user.id:
        abort(403)

    db.session.delete(pdf)
    db.session.commit()

    log_message = f'O usuário chamado {current_user.username} deletou o PDF {pdf_id}.'
    adicionar_entrada_log(log_message)

    flash('PDF deletado com sucesso!', 'success')
    return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    log_message = f'O usuário chamado {current_user.username} saiu do sistema.'
    adicionar_entrada_log(log_message)

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

        new_s_pdf = SignedPdf(
            user = current_user.id,
            pub_key = signatureID
        )

        db.session.add(new_s_pdf)
        db.session.commit()

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
        file = request.files["pdf"]
        if file.filename == "":
            return render_template("sign_pdf.html", error="Você precisa selecionar um PDF para assinar.")

        output_pdf = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(output_pdf) 

        name = request.form["name"]

        load(name)

        id = str(generate_key_hash(name))

        log_message = f'O usuário chamado {current_user.username} assinou um PDF com a chave {id}.'
        adicionar_entrada_log(log_message)

        return send_file(sign_file(output_pdf,id,300,100), as_attachment=True)
    

@app.route('/check_pdf_signature', methods=['POST'])
def check_pdf_signature():
    try:
        chave_procurada = request.form.get('chave_procurada')

        resultado = SignedPdf.query.filter(SignedPdf.pub_key == chave_procurada).first()

        if resultado:
            log_message = f'A chave {chave_procurada} foi buscada e considerada válida!'
            adicionar_entrada_log(log_message)
            flash('Assinatura válida', 'success')
            return redirect(url_for('index'))
        else:
            log_message = f'A chave {chave_procurada} foi buscada e considerada não válida!'
            adicionar_entrada_log(log_message)
            flash('Assinatura não válida', 'danger')
            return redirect(url_for('index'))

    except Exception as e:
        print({'mensagem': f'Erro: {str(e)}'})
        flash('Falha na checagem', 'danger')
        return redirect(url_for('index'))
    
def create_admin():
    if User.query.filter_by(username='admin').first() is None:
        admin_password = 'admin'
        key_hash = generate_key_hash('admin')
        admin = User(
            name = 'admin',
            username='admin',
            password=admin_password,
            key_hash=key_hash,
            admin=True
        )
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    port = int(os.getenv('PORT'), '5000')

    with app.app_context():
        db.create_all()

    app.run(host='0.0.0.0', port=port)