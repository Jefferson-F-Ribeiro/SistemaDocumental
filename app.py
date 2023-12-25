from flask import Flask, render_template, redirect, url_for, flash, send_file, abort
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, PdfModel
from forms import PdfForm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import io
from reportlab.pdfgen import canvas
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'chave_secreta_super_secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)