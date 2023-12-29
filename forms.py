from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired

class PdfForm(FlaskForm):
    content = TextAreaField('Conteúdo do PDF')
    submit = SubmitField('Salvar PDF')
