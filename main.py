from flask import Flask, render_template, request, url_for, flash, session, redirect, jsonify
from models import db, User, Food, Comment, Restaurant, Rating
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo

app = Flask(__name__, template_folder="templates")
app.config['SECRET_KEY'] = "thank_you"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../instance/database/foodieyumz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'
    
class Food(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    food_name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    food_image = db.Column(db.String(255))
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    is_recommended = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Food {self.food_name}>'

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    food_id = db.Column(db.Integer, db.ForeignKey('food.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<Rating {self.id}>'
    
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    food_id = db.Column(db.Integer, db.ForeignKey('food.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(255))
    submitted_by = db.Column(db.String(150))

    def __repr__(self):
        return f'<Comment {self.id}>'
    
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

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255))  # Image URL for restaurant
    foods = db.relationship('Food', backref='restaurant', lazy=True)

    def __repr__(self):
        return f'<Restaurant {self.name}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    deens_cafe = Restaurant.query.filter_by(name="Deen's Cafe").first()
    haji_tapah_cafe = Restaurant.query.filter_by(name="Haji Tapah Cafe").first()
    starbees = Restaurant.query.filter_by(name="Starbees").first()
    restaurants = Restaurant.query.all()
    return render_template('home.html', restaurants=restaurants, deens_cafe=deens_cafe, haji_tapah_cafe=haji_tapah_cafe, starbees=starbees)

@app.route('/restaurant/<int:restaurant_id>')
def restaurant_detail(restaurant_id):
    restaurant = Restaurant.query.get_or_404(restaurant_id)
    foods = Food.query.filter_by(restaurant_id=restaurant_id).all() 
    return render_template('restaurant_detail.html', restaurant=restaurant, foods=foods)

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
            flash('Email already exists. Please use a different one.', 'danger')
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
    user = User.query.get(current_user.id)
    db.session.delete(user)
    db.session.commit()
    logout_user()
    session.clear()
    flash('Account deleted successfully.','success')
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


@app.route('/food/<int:food_id>', methods=['GET'])
def food_detail(food_id):
    food = Food.query.get_or_404(food_id)
    ratings = Rating.query.filter_by(food_id=food.id).all()
    comments = Comment.query.filter_by(food_id=food.id).all()
    return render_template('food_detail.html', food=food, ratings=ratings, comments=comments)

@app.route('/food/<int:food_id>/rate', methods=['POST'])
@login_required
def rate_food(food_id):
    food = Food.query.get_or_404(food_id)
    rating = int(request.form.get('rating'))
    comment_text = request.form.get('comment')
    new_rating = Rating(food_id=food.id, user_id=current_user.id, rating=rating, comment=comment_text)
    db.session.add(new_rating)
    db.session.commit()
    flash('Rating and comment added successfully!', 'success')
    return redirect(url_for('food_detail', food_id=food_id))

#Comment on food
@app.route('/food/<int:food_id>/comment', methods=['POST'])
def add_comment(food_id):
    food = Food.query.get_or_404(food_id)
    comment_text = request.form['comment']
    rating = int(request.form['rating'])
    image_url = request.form.get('image_url')

    food = Food.query.get_or_404(food_id)
    comment_text = request.form['comment']
    rating = int(request.form['rating'])
    image_url = request.form.get('image_url')
    new_comment = Comment(
        comment=comment_text,
        rating=rating,
        image_url=image_url,
        user_id=current_user.id,
        food_id=food.id,
        submitted_by=current_user.username
    )

    db.session.add(new_comment)
    db.session.commit()
    
    flash('Comment added successfully!', 'success')
    return redirect(url_for('food_detail', food_id=food_id))

def sample_foods():
    deens_cafe = Restaurant.query.filter_by(name="Deen's Cafe").first()
    if deens_cafe:  
        db.session.add_all([
            Food(food_name='Roti Canai', description='A flatbread made from dough that is composed of fat (usually ghee), flour, and water.', food_image='static/images/roti_canai.jpg', restaurant_id=deens_cafe.id),
            Food(food_name='Nasi Lemak', description='A Malaysian dish consisting of rice cooked in coconut milk, served with anchovies, peanuts, boiled eggs, and sambal.', food_image='static/images/nasi_lemak.jpg', restaurant_id=deens_cafe.id),
            Food(food_name='Murtabak', description='A stuffed pancake or pan-fried bread, with fillings such as meat, eggs, and vegetables.', food_image='static/images/murtabak.jpg', restaurant_id=deens_cafe.id),
        ])
        db.session.commit()
    else:
        print("Deen's Cafe not found. Cannot add food items.")
    foods = [
        Food(food_name='Roti Canai', description='A flatbread made from dough that is composed of fat (usually ghee), flour, and water.', food_image='static/images/roti_canai.jpg', restaurant_id=deens_cafe.id),
        Food(food_name='Nasi Kandar', description='Steamed rice combined with an array of distinct curries, sides dishes, and gravies.', food_image='static/images/nasi_kandar.jpg', restaurant_id=deens_cafe.id)
    ]
    db.session.add_all(foods)
    db.session.commit()

@app.route('/restaurant/deens_cafe')
def deens_cafe_detail():
    deens_cafe = Restaurant.query.filter_by(name="Deen's Cafe").first()
    if not deens_cafe:
        flash('Restaurant not found!','danger')
        return redirect(url_for('home'))
    foods = Food.query.filter_by(restaurant_id=deens_cafe.id).all()
    return render_template('restaurant_detail.html', restaurant=deens_cafe, foods=foods)

@app.route('/restaurant/haji_tapah_cafe')
def haji_tapah_cafe_detail():
    haji_tapah_cafe = Restaurant.query.filter_by(name="Haji Tapah Cafe").first()
    if not haji_tapah_cafe:
        flash('Restaurant not found!','danger')
        return redirect(url_for('home'))
    foods = Food.query.filter_by(restaurant_id=haji_tapah_cafe.id).all()
    return render_template('restaurant_detail.html', restaurant=haji_tapah_cafe, foods=foods)

@app.route('/restaurant/starbees')
def starbees_detail():
    starbees = Restaurant.query.filter_by(name="Starbees").first()
    if not starbees:
        flash('Restaurant not found!','danger')
        return redirect(url_for('home'))
    foods = Food.query.filter_by(restaurant_id=starbees.id).all()
    return render_template('restaurant_detail.html', restaurant=starbees, foods=foods)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
