import os
from werkzeug.utils import secure_filename
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_migrate import Migrate
from flask_wtf.file import FileField, FileAllowed

# Flask setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define allowed extensions
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Models
class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    comments = db.relationship('Comment', backref='restaurant', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    picture = db.Column(db.String(150), nullable=True)  # Store picture filename
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __init__(self, username, password, is_admin=False):
        self.username = username
        self.password = generate_password_hash(password)
        self.is_admin = is_admin

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Flask-Login user loader
@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)

# Forms
class AdminSignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=64)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign up')

class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class EditRestaurantForm(FlaskForm):
    name = StringField('Restaurant Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')
    submit = SubmitField('Save Changes')

class AddRestaurantForm(FlaskForm):
    name = StringField('Restaurant Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')
    submit = SubmitField('Add Restaurant')

class CommentForm(FlaskForm):
    comment = TextAreaField('Add a Comment', validators=[DataRequired()])
    picture = FileField('Upload Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    submit = SubmitField('Submit Comment')

# Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied: Admins only.')
        return redirect(url_for('index'))

    form = AddRestaurantForm()

    if form.validate_on_submit():
        name = form.name.data
        description = form.description.data
        new_restaurant = Restaurant(name=name, description=description)
        db.session.add(new_restaurant)
        db.session.commit()
        flash('Restaurant added successfully.')
        return redirect(url_for('admin'))

    # Fetch all restaurants and display them
    restaurants = Restaurant.query.all()
    return render_template('admin_page.html', form=form, restaurants=restaurants)

@app.route('/admin/add_restaurant', methods=['GET', 'POST'])
@login_required
def add_restaurant():
    if not current_user.is_admin:
        flash('Access denied: Admins only.')
        return redirect(url_for('index'))

    form = AddRestaurantForm()  # Ensure you have this form defined

    if form.validate_on_submit():
        new_restaurant = Restaurant(
            name=form.name.data,
            description=form.description.data
        )
        db.session.add(new_restaurant)
        db.session.commit()
        flash('Restaurant added successfully.')
        return redirect(url_for('admin'))

    return render_template('add_restaurant.html', form=form)

@app.route('/admin/edit_restaurant/<int:restaurant_id>', methods=['GET', 'POST'])
@login_required
def edit_restaurant(restaurant_id):
    if not current_user.is_admin:
        flash('Access denied: Admins only.')
        return redirect(url_for('index'))

    restaurant = Restaurant.query.get_or_404(restaurant_id)
    form = EditRestaurantForm(obj=restaurant)

    if form.validate_on_submit():
        restaurant.name = form.name.data
        restaurant.description = form.description.data
        db.session.commit()
        flash('Restaurant details updated successfully.')
        return redirect(url_for('admin'))

    return render_template('edit_restaurant.html', form=form, restaurant=restaurant)

@app.route('/admin/delete_restaurant', methods=['POST'])
@login_required
def delete_restaurant():
    if not current_user.is_admin:
        flash('Access denied: Admins only.')
        return redirect(url_for('index'))

    restaurant_id = request.form.get('restaurant_id')
    restaurant = Restaurant.query.get_or_404(restaurant_id)

    db.session.delete(restaurant)
    db.session.commit()
    flash(f'Restaurant "{restaurant.name}" has been deleted.')
    return redirect(url_for('admin'))

@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    form = AdminSignupForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Maybe try to login or choose a different username.')
            return redirect(url_for('admin_signup'))
        new_user = User(username, password, is_admin=True)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Admin user created successfully. Please login to access the admin page.')
        return redirect(url_for('login'))
    return render_template('admin_signup.html', form=form)

@app.route('/index')
def index():
    return 'Welcome to the index page!'

@app.route('/main', methods=['GET'])
def main():
    restaurants = Restaurant.query.all()
    return render_template('main_page.html', restaurants=restaurants)

@app.route('/comment/<int:restaurant_id>', methods=['GET', 'POST'])
def comment_page(restaurant_id):
    restaurant = Restaurant.query.get_or_404(restaurant_id)
    form = CommentForm()

    if form.validate_on_submit():
        comment_content = form.comment.data
        picture = form.picture.data

        if picture and allowed_file(picture.filename):
            filename = secure_filename(picture.filename)
            picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            picture.save(picture_path)
        else:
            filename = None

        new_comment = Comment(content=comment_content, restaurant_id=restaurant_id, picture=filename)
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully.')
        return redirect(url_for('main'))

    return render_template('comment_page.html', restaurant=restaurant, form=form)

if __name__ == '__main__':
    app.run(debug=True)
