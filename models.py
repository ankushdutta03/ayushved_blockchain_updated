from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)  # Full name from signup
    username = db.Column(db.String(80), unique=True, nullable=False)  # Auto-generated from full name
    password_hash = db.Column(db.String(200), nullable=False)  # Hashed password
    mobile_number = db.Column(db.String(15), unique=True, nullable=False)  # For OTP-based reset
    created_on = db.Column(db.DateTime, default=datetime.utcnow)  # Signup timestamp

    herb_batches = db.relationship('HerbBatch', backref='user', lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"

class HerbBatch(db.Model):
    __tablename__ = 'herb_batch'

    id = db.Column(db.Integer, primary_key=True)
    herb_name = db.Column(db.String(120), nullable=False)
    collector = db.Column(db.String(120))
    farm_location = db.Column(db.String(256))
    collected_on = db.Column(db.DateTime, default=datetime.utcnow)  # Full timestamp
    latitude = db.Column(db.Float)        # Geo-tag: Latitude
    longitude = db.Column(db.Float)       # Geo-tag: Longitude
    geo_precision = db.Column(db.Float)   # Optional: GPS accuracy in meters
    notes = db.Column(db.Text)
    qr_code_data = db.Column(db.String(512))  # Encoded QR content or image path
    blockchain_tx = db.Column(db.String(256))  # Future Fabric integration

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<HerbBatch {self.id} {self.herb_name}>"