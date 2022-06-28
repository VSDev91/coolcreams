from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, URLField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditorField


# WTForm


class RegisterForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[Email(), Length(max=100)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class ContactForm(FlaskForm):
    name = StringField("Your name", validators=[DataRequired(), Length(max=100)])
    email = EmailField("Your email", validators=[Email(), Length(max=100)])
    phone = StringField("Phone Number", validators=[DataRequired(), Length(max=20)])
    website = URLField("Personal Website", validators=[URL(), Length(max=100)])
    body = CKEditorField("Quick Message", validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField("Submit")
