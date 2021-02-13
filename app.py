"""
This script runs the application using a development server.
It contains the definition of routes and views for the application.
"""

import json
import os
import sqlite3
from flask import Flask, redirect, request, url_for, render_template, flash, redirect
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
    UserMixin
    )
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Length, Email, EqualTo, email_validator, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# Make the WSGI interface available at the top level so wfastcgi can get it.
wsgi_app = app.wsgi_app
app.secret_key = 'replace later'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt()
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'replace-later'
#db.create_all(), db.drop_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
class User(db.Model, UserMixin):
    """User model"""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    #username = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(250), nullable=False)

    def __repr__(self):
        return f"User('{self.email}')"

class Session(db.Model):
    __tablename__ = "session"

    id = db.Column(db.Integer, primary_key=True)
    session = db.Column(db.String(250), unique=True, nullable=False)

class Registered(db.Model):
     __tablename__ = "session"

    id = db.Column(db.Integer, primary_key=True)
    registered = db.Column(db.Boolean, unique=True, nullable=False)

class RegistrationForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password =  PasswordField('Password', validators=[DataRequired()])
    confirm_password =  PasswordField('Confirm Password',
                                      validators=[DataRequired(), EqualTo('password')])
    submit =  SubmitField('Sign Up')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('It appears you have been registered before, proceed to login')

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password =  PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit =  SubmitField('Login')

class UpdateAccountForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit =  SubmitField('Update')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('This is a forbidden action')

@app.route('/about')
def about():
    """Renders a sample page."""
    return render_template('about.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user = User(email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit:
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('login unsuccessful, please check email and password', 'danger')
    return render_template('login.html', title='Register', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UpdateAccountForm()
    image_file = url_for('static', filename='profilepics/' + current_user.image_file)
    return render_template('dashboard.html', title='Dashboard', image_file=image_file, form=form)


if __name__ == '__main__':
    import os
    HOST = os.environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(os.environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    app.run(HOST, PORT)
