from flask import request, jsonify, redirect, session
from app.services.auth_service import get_oidc_login_url, process_oidc_callback, exchange_code_for_token, get_user_info
from app.utils.response_util import success_response, error_response
from app.schemas.auth_schema import AuthCallbackRequest, TokenExchangeRequest
from flask_jwt_extended import jwt_required
from pydantic import ValidationError
from flasgger import swag_from

def login():
    """Redirect to OpenID Connect login"""
    return redirect(get_oidc_login_url())

@swag_from("swagger_docs/auth_callback.yml")
def callback():
    try:
        request_data = AuthCallbackRequest(**request.args)
    except ValidationError as e:
        return jsonify(error_response(f"Invalid request data: {e.errors()}")), 400

    try:
        tokens = process_oidc_callback(request_data.code)
        session['access_token'] = tokens['openid_access_token']  # Store access token
        return jsonify(success_response("Authentication successful", tokens)), 200
    except ValueError as e:
        return jsonify(error_response(str(e), 401)), 401
    except Exception as e:
        return jsonify(error_response("Internal Server Error", 500)), 500

@swag_from("swagger_docs/auth_token.yml")
def token():
    try:
        data = request.get_json()
        validated_data = TokenExchangeRequest(**data)
    except ValidationError as e:
        return jsonify(error_response(f"Invalid request data: {e.errors()}")), 400

    try:
        tokens = exchange_code_for_token(validated_data.code)
        return jsonify(success_response("Token exchange successful", tokens)), 200
    except ValueError as e:
        return jsonify(error_response(str(e), 401)), 401

@jwt_required()
@swag_from("swagger_docs/auth_userinfo.yml")
def userinfo():
    access_token = session.get("access_token")
    if not access_token:
        return jsonify(error_response("Unauthorized")), 401

    user_info = get_user_info(access_token)
    return jsonify(success_response("User info retrieved successfully", user_info)), 200

@jwt_required()
@swag_from("swagger_docs/auth_logout.yml")
def logout():
    session.clear()
    return jsonify(success_response("User logged out successfully")), 200
