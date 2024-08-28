from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    comments = db.relationship('Comment', backref='commenter', cascade="all, delete-orphan", lazy=True)
    notifications = db.relationship('Notification', back_populates='user', cascade="all, delete-orphan", lazy=True, overlaps="user_notifications")
    reports = db.relationship('Report', back_populates='user', cascade="all, delete-orphan", lazy=True, overlaps="user_reports")

    def __repr__(self):
        return f'<User {self.name}>'

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class Food(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    food_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    food_image = db.Column(db.String(255))
    username = db.Column(db.String(100), db.ForeignKey('user.name', name='fk_food_user'), nullable=False)
    comments = db.relationship('Comment', backref='food', cascade="all, delete-orphan", lazy=True)
    reports = db.relationship('Report', back_populates='food', cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Food {self.name}>'
    
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(255))
    submitted_by = db.Column(db.String(100), nullable=False)
    food_id = db.Column(db.Integer, db.ForeignKey('food.id', name='fk_comment_food'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_comment_user'), nullable=False)
    reports = db.relationship('Report', back_populates='comment', cascade="all, delete-orphan")

    def __repr__(self):
        return f"Comment('{self.comment}', '{self.rating}')"

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_report_user'), nullable=False)
    food_id = db.Column(db.Integer, db.ForeignKey('food.id', name="fk_report_food"), nullable=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id', name='fk_report_comment'), nullable=True)
    report_text = db.Column(db.String(500), nullable=False)
    reviewed = db.Column(db.Boolean, default=False)
    approved = db.Column(db.Boolean, default=False)
    notified = db.Column(db.Boolean, default=False)

    user = db.relationship('User', back_populates='reports', overlaps="reports,user_reports")
    food = db.relationship('Food', back_populates='reports', overlaps="reports,food_reports")
    comment = db.relationship('Comment', back_populates='reports', overlaps="reports,comment_reports")

