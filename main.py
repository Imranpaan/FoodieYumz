from flask import Flask, render_template, request, url_for, flash, session, redirect
from models import db, User, Food, Comment,
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
import os


app = Flask(__name__, template_folder="templates")
app.secret_key = "Thank you"
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)


#Register An Account
@app.route('/register', methods=('GET','POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        #Check if user exist edy
        user_exist = User.query.filter_by(username=username).first()
        if user_exist:
            flash('Username already exists. Please try another one.','danger')
            return redirect(url_for('register'))
            
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash('Successfully Registered! Please log in to view the foodies!', 'success')
        return redirect(url_for('login'))        
        
    return render_template('register.html')

#Login
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.generate_password_hash(user.password, password):
            session['username'] = user.username
            flash('Successfully Log In!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Failure to Login. Please check your username and password.', 'danger')
            return redirect(url_for('login'))
        
    return render_template('login.html')

#Log Out
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

#Delete acc
@app.route('/delete_account', methods=['POST'])
def delete_account():
    username = session.get('username')
    if not username:
        flash('You need to log in in order to delete your account.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=username).first()
    db.session.delete(user)
    db.session.commit()

    session.pop('username', None)
    flash('Successfully Deleted Your Account!', 'success')
    return redirect(url_for('register'))

#Change p/w
@app.route('/change_password', methods=['GET','POST'])
def change_password():
    username = session.get('username')
    if not username:
        flash('You need to log in in order to change your password.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        user = User.query.get(username)

        if bcrypt.check_password_hash(user.password, current_password):
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()

            flash('You have successfully changed your password.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))
        
    return render_template('change_password.html')

#Comment on foodie
@app.route('/food/<int:food_id>/comment', methods=['POST'])
def add_comment(food_id):
    if 'username' not in session:
        flash('You need to log in to comment.', 'danger')
        return redirect(url_for('login'))

    food = Food.query.get_or_404(food_id)
    comment_text = request.form['comment']
    rating = int(request.form['rating'])  # Assuming rating is an integer
    image_url = request.form.get('image_url')
    username = User.query.filter_by(username=session['username']).first().id

    new_comment = Comment(
        comment=comment_text,
        rating=rating,
        image_url=image_url,
        username=username,
        food_id=food_id,
        submitted_by=session['username'],
    )

    db.session.add(new_comment)
    db.session.commit()
    
    flash('Comment added successfully!', 'success')
    return redirect(url_for('food_detail', food_id=food_id))

@app.route('/food/<int:food_id>')
def food_detail(food_id):
    food = Food.query.get_or_404(food_id)
    return render_template('food_detail.html', food=food)

