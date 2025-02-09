from .database import db

class GeoStatData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(100), nullable=False)
    population_density = db.Column(db.Integer, nullable=False)
    average_income = db.Column(db.Integer, nullable=False)
    geographical_features = db.Column(db.String(255), nullable=False)