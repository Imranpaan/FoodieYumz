from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    comments = db.relationship('Comment', backref='commenter', cascade="all, delete-orphan", lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Food(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    food_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    food_image = db.Column(db.String(255))

    def __repr__(self):
        return f'<Food {self.name}>'
    
class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    food_id = db.Column(db.Integer, db.ForeignKey('food.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<Rating {self.rating} for Food {self.food_id}>'
    
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    food_id = db.Column(db.Integer, db.ForeignKey('food.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    fimage_url = db.Column(db.String(255))
    submitted_by = db.Column(db.String(150))

    def __repr__(self):
        return f'<Comment by User {self.user_id} on Food {self.food_id}>'

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255))

    foods = db.relationship('Food', backref='restaurant', lazy=True)

    def __repr__(self):
        return f'<Restaurant {self.name}>'