from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from .models import GeoStatData, db

geostat_bp = Blueprint('geostat', __name__)

@geostat_bp.route('/data', methods=['GET'])
@jwt_required()
def get_geostat_data():
    data = GeoStatData.query.all()
    result = [{
        "location": d.location,
        "population_density": d.population_density,
        "average_income": d.average_income,
        "geographical_features": d.geographical_features
    } for d in data]
    return jsonify(result)