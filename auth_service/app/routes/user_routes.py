from flask import Blueprint
from flask_jwt_extended import jwt_required
from app.controllers.user_controller import register_user, get_user, assign_role

user_bp = Blueprint('user', __name__)

user_bp.route('/register', methods=['POST'])(register_user)
user_bp.route('', methods=['GET'])(jwt_required()(get_user))
user_bp.route('/assign-role', methods=['POST'])(jwt_required()(assign_role))
