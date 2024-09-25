
import os
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_migrate import Migrate
from flask_wtf.file import FileField, FileAllowed
import random
from sqlalchemy.sql import func

# Flask setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///foodieyumz.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user_login'  # Set default login view for users

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
    picture = db.Column(db.String(150), nullable=True)
    comments = db.relationship('Comment', backref='restaurant', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    picture = db.Column(db.String(150), nullable=True)  # Store picture filename
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
class Admin(UserMixin, db.Model):
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
    return Admin.query.get(int(user_id)) 

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

class AddRestaurantForm(FlaskForm):
    name = StringField('Restaurant Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')
    picture = FileField('Upload Restaurant Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    submit = SubmitField('Add Restaurant')

class EditRestaurantForm(FlaskForm):
    name = StringField('Restaurant Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')
    picture = FileField('Upload Restaurant Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    submit = SubmitField('Save Changes')

class CommentForm(FlaskForm):
    comment = TextAreaField('Add a Comment', validators=[DataRequired()])
    picture = FileField('Upload Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    rating = IntegerField('Rating (1-5)', validators=[DataRequired()])
    submit = SubmitField('Submit Comment')

# Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        admin = Admin.query.filter_by(username=username).first()

        # Debugging logs
        print(f'Attempting login for username: {username}')
        print(f'Admin found: {admin is not None}')

        if admin and admin.check_password(password):  # Check password here
            login_user(admin)
            return redirect(url_for('admin'))  # or redirect to another page
        else:
            flash('Invalid username or password')
            return redirect(url_for('admin_login'))  # Redirect to clear form

    return render_template('admin_login.html', form=form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('admin_login'))  # Redirect to user login page

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # Check if user is logged in
    if not current_user.is_authenticated:
        return redirect(url_for('admin_login'))

    # Check if the user is an admin
    if not current_user.is_admin:
        flash('Access denied: Admins only.')
        return redirect(url_for('index'))

    form = AddRestaurantForm()

    if form.validate_on_submit():
        filename = None
        if form.picture.data:
            picture = form.picture.data
            if allowed_file(picture.filename):
                filename = secure_filename(picture.filename)
                picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                picture.save(picture_path)
        
        new_restaurant = Restaurant(
            name=form.name.data,
            description=form.description.data,
            picture=filename
        )
        db.session.add(new_restaurant)
        db.session.commit()
        flash('Restaurant added successfully.')
        return redirect(url_for('admin'))

    # Search query
    search_query = request.args.get('search', '')

    if search_query:
        # When search, filter restaurants by name and sort them
        restaurants = Restaurant.query.filter(Restaurant.name.ilike(f'%{search_query}%')).order_by(Restaurant.name).all()
    else:
        # No search, get all restaurants and sort by name
        restaurants = Restaurant.query.order_by(Restaurant.name).all()

    return render_template('admin_page.html', form=form, restaurants=restaurants, search_query=search_query)



@app.route('/admin/add_restaurant', methods=['GET', 'POST'])
@login_required
def add_restaurant():
    if not current_user.is_admin:
        flash('Access denied: Admins only.')
        return redirect(url_for('index'))

    form = AddRestaurantForm()

    if form.validate_on_submit():
        filename = None
        if form.picture.data:
            picture = form.picture.data
            if allowed_file(picture.filename):
                filename = secure_filename(picture.filename)
                picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                picture.save(picture_path)
        
        new_restaurant = Restaurant(
            name=form.name.data,
            description=form.description.data,
            picture=filename
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

        picture = form.picture.data
        if isinstance(picture, FileStorage) and allowed_file(picture.filename):
            filename = secure_filename(picture.filename)
            picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            picture.save(picture_path)
            restaurant.picture = filename

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

    # Delete comments associated with the restaurant
    comments = Comment.query.filter_by(restaurant_id=restaurant_id).all()
    for comment in comments:
        db.session.delete(comment)

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
        existing_admin = Admin.query.filter_by(username=username).first()
        if existing_admin:
            flash('Username already exists. Maybe try to login or choose a different username.')
            return redirect(url_for('admin_signup'))
        new_admin = Admin(username, password, is_admin=True)
        db.session.add(new_admin)
        db.session.commit()
        login_user(new_admin)
        flash('Admin user created successfully. Please login to access the admin page.')
        return redirect(url_for('admin_login'))
    return render_template('admin_signup.html', form=form)

@app.route('/restaurant/<int:restaurant_id>', methods=['GET'])
def restaurant_page(restaurant_id):
    restaurant = Restaurant.query.get_or_404(restaurant_id)
    return render_template('restaurant_page.html', restaurant=restaurant)

@app.route('/submit_comment/<int:restaurant_id>', methods=['POST'])
def submit_comment(restaurant_id):
    content = request.form['content']
    picture = request.files.get('picture')
    rating = request.form.get('rating', type=int)

    # Create a new Comment object
    new_comment = Comment(content=content, restaurant_id=restaurant_id, rating=rating)

    if picture:
        # Save the picture file and attach the filename to the comment
        picture_filename = secure_filename(picture.filename)
        picture.save(os.path.join(app.config['UPLOAD_FOLDER'], picture_filename))
        new_comment.picture = picture_filename

    # Add the comment to the database
    db.session.add(new_comment)
    db.session.commit()

    # Redirect back to the restaurant page
    return redirect(url_for('restaurant_page', restaurant_id=restaurant_id))


@app.route('/index')
def index():
    return 'Welcome to the index page!'

@app.route('/main', methods=['GET'])
def main():
    search_query = request.args.get('search', '')
    
    if search_query:
        # Search query, filter restaurants by name and sort them
        restaurants = Restaurant.query.filter(Restaurant.name.ilike(f'%{search_query}%')).order_by(Restaurant.name).all()
    else:
        # No search, get all restaurants and sort by name
        restaurants = Restaurant.query.order_by(Restaurant.name).all()
    
    return render_template('main_page.html', restaurants=restaurants, search_query=search_query)


@app.route('/comment/<int:restaurant_id>', methods=['GET', 'POST'])
def comment_page(restaurant_id):
    restaurant = Restaurant.query.get_or_404(restaurant_id)
    form = CommentForm()

    if form.validate_on_submit():
        comment_content = form.comment.data
        picture = form.picture.data

        # Get the rating from the form
        rating = request.form.get('rating')  # Retrieve the rating from the form

        if not rating:
            flash('Please select a rating!', 'error')
            return redirect(url_for('comment_page', restaurant_id=restaurant_id))

        if picture and allowed_file(picture.filename):
            filename = secure_filename(picture.filename)
            picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            picture.save(picture_path)
        else:
            filename = None

        # Include the rating when creating a new comment
        new_comment = Comment(content=comment_content, restaurant_id=restaurant_id, picture=filename, rating=rating)
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully.')

        # Redirect to the specific restaurant page
        return redirect(url_for('restaurant_page', restaurant_id=restaurant_id))  # Change this to your restaurant page route

    return render_template('comment_page.html', restaurant=restaurant, form=form)



@app.route('/delete-comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    print(f"Deleting comment: {comment.id}, restaurant_id: {comment.restaurant_id}")

    try:
        db.session.delete(comment)
        db.session.commit()
        flash('Comment deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()  # Rollback the session on error
        flash('Failed to delete comment: ' + str(e), 'error')
    
    return redirect(url_for('admin'))


from sqlalchemy.sql import func

@app.route('/homepage')
def homepage():
    #three random restaurants
    recommended_restaurants = Restaurant.query.order_by(func.random()).limit(3).all()
    return render_template('homepage.html', recommended_restaurants=recommended_restaurants)


if __name__ == '__main__':
    app.run(debug=True)