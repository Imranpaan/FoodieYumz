from flask import Flask, render_template, request, url_for, flash, session, redirect, jsonify
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Optional
import os
from flask_wtf import FlaskForm, CSRFProtect
from werkzeug.utils import secure_filename
import time
from sqlalchemy import Enum
from models import User, SignupForm, LoginForm, ChangePasswordForm, UpdateProfileForm

app = Flask(__name__, template_folder="templates")
app.config['SECRET_KEY'] = "thank_you"

basedir = os.path.abspath(os.path.dirname(__file__))
database_dir = os.path.join(basedir, "instance/database")
os.makedirs(database_dir, exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(database_dir, "foodieyumz.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    profile_picture = db.Column(db.String(255), default='static/images/user_default_icon.jpg')
    bio = db.Column(db.String(255), default="This user is too lazy, he/she hasn't added any bio yet.")

    def __repr__(self):
        return f'<User {self.username}>'
    
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')

class UpdateProfileForm(FlaskForm):
    profile_picture = StringField('Profile Picture URL', validators=[Optional()])
    bio = TextAreaField('Bio', validators=[Optional()])
    submit = SubmitField('Update Profile')

@app.route('/main')
def main():
    return render_template('main.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/home')
def home():
    return render_template('home.html')

#Signup An Account
@app.route('/signup', methods=('GET','POST'))
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        #Check if username exist edy
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please try another one.','danger')
            return redirect(url_for('signup'))
        
        #Check if email exist edy
        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please use another one.', 'danger')
            return redirect(url_for('signup'))
          
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Successfully Registered! Please log in to view the foodies!', 'success')
        session.clear()
        return redirect(url_for('login'))        
        
    return render_template('signup.html', form=form)

#Login
@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Successfully Logged In!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Invalid login credentials. Please try again.','danger')
            return redirect(url_for('login'))
    
    return render_template('login.html', form=form)

#Log Out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Successfully logged out.', 'success')
    return redirect(url_for('home'))

#Delete acc
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    password = request.form.get('password')
    user = User.query.get(current_user.id)

    if user and bcrypt.check_password_hash(user.password, password):
        db.session.delete(user)
        db.session.commit()
        logout_user()
        session.clear()
        flash('Account deleted successfully.', 'success')
        return redirect(url_for('home'))
    else:
        flash('Invalid password. Account not deleted.', 'danger')
        return redirect(url_for('home'))
    
#Change p/w
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data
        user = User.query.get(current_user.id)

        if user and bcrypt.check_password_hash(user.password, current_password):
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()

            flash('Password changed successfully!', 'success')
            session.clear()
            return redirect(url_for('home'))
        else:
            flash('Incorrect current password.', 'danger')
            return redirect(url_for('change_password'))

    return render_template('change_password.html', form=form)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/profile', methods=['GET'])
@login_required
def view_profile():
    return render_template('profile.html', user=current_user)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                if current_user.profile_picture != 'static/images/user_default_icon.jpg':
                    old_file_path = os.path.join(app.root_path, current_user.profile_picture[1:]) 
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)
                
                filename = secure_filename(file.filename)
                unique_filename = str(int(time.time())) + "_" + filename
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                current_user.profile_picture = url_for('static', filename='uploads/' + unique_filename)

        current_user.bio = form.bio.data
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('edit_profile.html', title='Edit Profile' ,form=form)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.context_processor
def inject_user():
    return dict(current_user=current_user)

@app.route('/profile/reset', methods=['POST'])
@login_required
def reset_profile():
    if current_user.profile_picture != 'static/images/user_default_icon.jpg':
        file_path = os.path.join(app.root_path, current_user.profile_picture[1:])
        if os.path.exists(file_path):
            os.remove(file_path)

    current_user.profile_picture = 'static/images/user_default_icon.jpg'
    current_user.bio = "This user is too lazy, he/she hasn't added any bio yet."
    db.session.commit()
    
    flash('Profile has been reset to default settings.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)


#database inside instance/database/foodieyumz.db is haiyuan's