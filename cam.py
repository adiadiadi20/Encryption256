from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from cryptor import Decryptor
import matplotlib.pyplot as plt
from PIL import Image
import io
import base64
import os

app = Flask(__name__)


# Configure the SQLAlchemy part of the app instance
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Use your desired database URI
app.config['SECRET_KEY'] = 'thisisasecretkey'  # Optional: secret key for session management

bcrypt = Bcrypt(app)
# Create the SQLAlchemy db instance
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Define a User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    usernamereg = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    passwordreg = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submitreg = SubmitField('Register')

    def validate_usernamereg(self, usernamereg):
        existing_user_username = User.query.filter_by(username=usernamereg.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    usernamelogin = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    passwordlogin = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submitlogin = SubmitField('Login')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.usernamelogin.data).first()
        if user and bcrypt.check_password_hash(user.password, form.passwordlogin.data):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html', login_form=form, register_form=RegisterForm())


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.passwordreg.data).decode('utf-8')
        new_user = User(username=form.usernamereg.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('login.html', login_form=LoginForm(), register_form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    if not os.path.exists('example'):
        return render_template('error.html')

    else:
        try:
            decrypted_path = 'example/decrypt_image'
            key_path = 'example/encryption_key.bin'
            iv_path = 'example/initialization_vector.bin'
            decryptor = Decryptor(path='example/encrypted_file', outname=decrypted_path, create=False, _key=key_path, _iv=iv_path)
            decryptor()
            encryption_key = decryptor._key.hex()
            image1 = Image.open('example\crypted_image.jpg')
            image1_bytes = io.BytesIO()
            image1.save(image1_bytes, format='JPEG')
            image1_base64 = base64.b64encode(image1_bytes.getvalue()).decode('utf-8')

            image2 = Image.open('example\decrypt_image.jpg')
            image2_bytes = io.BytesIO()
            image2.save(image2_bytes, format='JPEG')
            image2_base64 = base64.b64encode(image2_bytes.getvalue()).decode('utf-8')
            return render_template('dashboard.html', encryption_key=encryption_key, image1=image1_base64, image2=image2_base64)
        except Exception as e:
            return render_template('error.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=80)

