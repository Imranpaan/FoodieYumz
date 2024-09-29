from flask import Flask, render_template, request, url_for, flash, session, redirect, jsonify, abort
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Optional, Length
import os
from flask_wtf import FlaskForm, CSRFProtect
from werkzeug.utils import secure_filename
import time
from sqlalchemy import Enum
from werkzeug.datastructures import FileStorage
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.file import FileField, FileAllowed
from sqlalchemy.orm import joinedload

app = Flask(__name__, template_folder="templates")

basedir = os.path.abspath(os.path.dirname(__file__))
database_dir = os.path.join(basedir, "instance", "database")
os.makedirs(database_dir, exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(database_dir, "foodieyumz.db")}'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "thank_you"

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
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    picture = db.Column(db.String(150), nullable=True)
    comments = db.relationship('Comment', backref='restaurant', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer)
    picture = db.Column(db.String(150))
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationship to User model
    user = db.relationship('User', backref='comments')

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

with app.app_context():
    db.create_all()

@login_manager.user_loader
def user_loader(user_id):
    user = User.query.get(int(user_id))
    if user:
        return user
    return Admin.query.get(int(user_id)) 

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/main', methods=['GET'])
def main():
    search_query = request.args.get('search', '')
    
    if search_query:
        # Search query, filter restaurants by name and sort them
        restaurants = Restaurant.query.filter(Restaurant.name.ilike(f'%{search_query}%')).order_by(Restaurant.name).all()
    else:
        # No search, get all restaurants and sort by name
        restaurants = Restaurant.query.order_by(Restaurant.name).all()
    
    return render_template('main.html', restaurants=restaurants, search_query=search_query)

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
        
        admin = Admin.query.filter_by(username=email).first()   
        if admin and bcrypt.check_password_hash(admin.password, password):
            login_user(admin)  # Log in the admin user
            flash('Admin Successfully Logged In!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        flash('Invalid login credentials. Please try again.', 'danger')
        return redirect(url_for('login'))
    
    return render_template('login.html', form=form)

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

@app.route('/restaurant_listing')
def restaurant_listing():
    return render_template('main.html')

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

                original_filename = secure_filename(file.filename)
                base_filename, ext = os.path.splitext(original_filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)

                count = 0
                while os.path.exists(file_path):
                    count += 1
                    new_filename = f"{base_filename}_{count}{ext}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                                   
                file.save(file_path)
                current_user.profile_picture = url_for('static', filename='uploads/' + os.path.basename(file_path))   

        current_user.bio = form.bio.data
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('edit_profile.html', title='Edit Profile' ,form=form)

@app.route('/user/<int:user_id>', endpoint='profile')
@login_required
def profile(user_id):
    user = User.query.get_or_404(user_id)
    if not current_user.is_authenticated:
        abort(403)
    return render_template('profile.html', user=user)

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
@app.route('/admin/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Successfully logged out.', 'success')
    return redirect(url_for('admin_login' if request.path.startswith('/admin') else 'login'))

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
    restaurant = Restaurant.query.filter_by(id=restaurant_id).first_or_404()
    restaurant.comments = Comment.query.options(joinedload(Comment.user)).filter_by(restaurant_id=restaurant_id).all()
    return render_template('restaurant_page.html', restaurant=restaurant)

@app.route('/submit_comment/<int:restaurant_id>', methods=['POST'])
def submit_comment(restaurant_id):
    content = request.form['content']
    picture = request.files.get('picture')
    rating = request.form.get('rating', type=int)
    
    new_comment = Comment(
        content=content, 
        rating=rating, 
        restaurant_id=restaurant_id, 
        user_id=current_user.id
    )

    if picture:
        # Save the picture file and attach the filename to the comment
        picture_filename = secure_filename(picture.filename)
        picture.save(os.path.join(app.config['UPLOAD_FOLDER'], picture_filename))
        new_comment.picture = picture_filename  # Save the filename to the comment

    # Add the comment to the database
    db.session.add(new_comment)
    db.session.commit()
    # Redirect back to the restaurant page
    return redirect(url_for('restaurant_page', restaurant_id=restaurant_id))

@app.route('/index')
def index():
    return 'Welcome to the index page!'

@app.route('/main', methods=['GET'])
def main_view():
    search_query = request.args.get('search', '')
    
    if search_query:
        # Search query, filter restaurants by name and sort them
        restaurants = Restaurant.query.filter(Restaurant.name.ilike(f'%{search_query}%')).order_by(Restaurant.name).all()
    else:
        # No search, get all restaurants and sort by name
        restaurants = Restaurant.query.order_by(Restaurant.name).all()
    
    return render_template('main.html', restaurants=restaurants, search_query=search_query)


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


if __name__ == '__main__':
    app.run(debug=True)