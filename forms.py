from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

class PdfForm(FlaskForm):
    content = TextAreaField('Conteúdo do PDF')
    submit = SubmitField('Salvar PDF')

class SignatureForm(FlaskForm):
    pdf_file = FileField('PDF File', validators=[FileRequired()])
    signature_id = StringField('Signature ID', validators=[DataRequired()])
    name = StringField('Your Name', validators=[DataRequired()])
    reason = StringField('Reason', default='Testing')
    location = StringField('Location', default='City')
    submit = SubmitField('Sign PDF')