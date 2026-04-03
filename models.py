from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(50), nullable=False)
    theme = db.Column(db.String(10), default="dark")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Security metadata
    failed_attempts = db.Column(db.Integer, default=0)
    last_failed_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(100), nullable=True)
    last_login_ua = db.Column(db.String(300), nullable=True)


class OperationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    operation = db.Column(db.String(50))
    data_type = db.Column(db.String(50))
    details = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
