from flask import Blueprint
from app.controllers.auth_controller import login, callback, userinfo, logout, token

auth_bp = Blueprint('auth', __name__)

auth_bp.route('/login', methods=['GET'])(login)
auth_bp.route('/callback', methods=['GET'])(callback)
auth_bp.route('/userinfo', methods=['GET'])(userinfo)
auth_bp.route('/logout', methods=['POST'])(logout)
auth_bp.route('/token', methods=['GET'])(token)
