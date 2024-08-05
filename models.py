from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.dialects.postgresql import ARRAY
from flask_login import UserMixin

db = SQLAlchemy()


class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    profile_photo_url = db.Column(db.String(120), nullable=True)
    reset_token = db.Column(db.String(120), nullable=True)


class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    users = db.Column(ARRAY(db.Integer), nullable=False)
    chat_key = db.Column(db.String, unique=True, nullable=False)
    inserted_date = db.Column(db.DateTime, nullable=False, default=datetime.now())


class Messages(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, nullable=False)
    receiver_id = db.Column(db.Integer, nullable=False)
    message = db.Column(db.Text, nullable=False)
    inserted_date = db.Column(db.DateTime, nullable=False, default=datetime.now())
    chat_id = db.Column(db.String(80), db.ForeignKey('chat.chat_key'), nullable=False)
