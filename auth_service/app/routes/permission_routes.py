from flask import Blueprint
from flask_jwt_extended import jwt_required
from app.controllers.permission_controller import add_permission, list_permissions

permission_bp = Blueprint('permission', __name__)

permission_bp.route('/add', methods=['POST'])(jwt_required()(add_permission))
permission_bp.route('/list', methods=['GET'])(jwt_required()(list_permissions))
