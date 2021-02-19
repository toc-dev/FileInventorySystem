"""
This script runs the application using a development server.
It contains the definition of routes and views for the application.
"""
import secrets
from PIL import Image
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
from sqlalchemy.orm import relationship
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

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    #username = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(250), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), default=2, nullable=False)

    user_registration = relationship('Registration', backref='registration_user', lazy='dynamic')

    def __repr__(self):
        return f"User('{self.email}')"

class Roles(db.Model):

    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    roles = db.Column(db.String(25))
    user_role = relationship('User', backref='user_role', lazy='dynamic')
 
class Year(db.Model):
     __tablename__ = "year"

     id = db.Column(db.Integer, primary_key=True)
     year = db.Column(db.Integer)
     year_registration = relationship('Registration', backref='year_registration', lazy='dynamic')

class Session(db.Model):
    __tablename__ = "session"

    id = db.Column(db.Integer, primary_key=True)
    session = db.Column(db.String(250), unique=True, nullable=False)
    
    session_registration = relationship('Registration', backref='registration_session', lazy='dynamic')

class Semester(db.Model):
    __tablename__ = "semester"

    id = db.Column(db.Integer, primary_key=True)
    semester = db.Column(db.String(250), unique=True, nullable=False)

class Registered(db.Model):
    __tablename__ = "registered"

    id = db.Column(db.Integer, primary_key=True)
    registered = db.Column(db.Boolean, default=False, nullable=False)
    register_registration = relationship('Registration', backref='registration_register', lazy='dynamic')

class Registration(db.Model):
    __tablename__ = "registration"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('session.id'), nullable=False)
    year_id = db.Column(db.Integer, db.ForeignKey('year.id'), nullable=False)
    registered_id = db.Column(db.Integer, db.ForeignKey('registered.id'), nullable=False)

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
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit =  SubmitField('Update')

class MarkAsRegistered(FlaskForm):
    registered = BooleanField('Registered')
    submit = SubmitField('Register')


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

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profilepics', picture_fn)
    
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    
    i.save(picture_path)
    return picture_fn

@app.route('/search', methods=['POST', 'GET'])
def search():
    #curr_user = User.query.get(current_user)
    #if curr_user.role_id == 2:
    #    flash('You cannot even perform this action', 'unsuccessful')
    return render_template('search.html')

@app.route('/results', methods=['POST'])
def results():
    if request.method == 'POST':
        emails = request.form.get('email')
        results = User.query.filter(User.email.match(emails))
        print(results)
     
        if emails in results:
            user_email = results.email
        flash("Email not found")


    return render_template('results.html', email=user_email)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        db.session.commit()
        flash('Your picture has been updated!', 'success')
        return redirect(url_for('dashboard'))
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
