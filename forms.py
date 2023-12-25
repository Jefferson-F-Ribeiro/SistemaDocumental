from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField

class PdfForm(FlaskForm):
    content = TextAreaField('Conteúdo do PDF')
    submit = SubmitField('Salvar PDF')