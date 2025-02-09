from flask import Blueprint
from flask_jwt_extended import jwt_required
from app.controllers.role_controller import add_role, list_roles

role_bp = Blueprint('role', __name__)

role_bp.route('/add', methods=['POST'])(jwt_required()(add_role))
role_bp.route('/list', methods=['GET'])(jwt_required()(list_roles))
