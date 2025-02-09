from flask import request, jsonify

from app import db
from app.models.role_model import Role
from app.models.user_model import User
from app.models.user_role_mapping import UserRoleMapping
from app.services.user_service import create_user, get_user_by_email
from app.utils.response_util import success_response, error_response
from flask_jwt_extended import jwt_required
from pydantic import ValidationError
from app.schemas.user_schema import UserRegisterRequest, UserRoleAssignmentRequest
from flasgger import swag_from

@swag_from("swagger_docs/user_register.yml")
def register_user():
    """Register a new user."""
    try:
        data = request.get_json()
        validated_data = UserRegisterRequest(**data)
    except ValidationError as e:
        return jsonify(error_response(f"Invalid request data: {e.errors()}")), 400

    user = create_user(validated_data.email, validated_data.password)
    if not user:
        return jsonify(error_response("User already exists")), 400

    return jsonify(success_response("User registered successfully", {"user_id": user.id, "email": user.email})), 201

@jwt_required()
@swag_from("swagger_docs/user_get.yml")
def get_user():
    """Get user details (Protected API)"""
    email = request.args.get("email")
    if not email:
        return jsonify(error_response("Email is required")), 400

    user = get_user_by_email(email)
    if not user:
        return jsonify(error_response("User not found")), 404

    return jsonify(success_response("User found", {"user_id": user.id, "email": user.email})), 200

@jwt_required()
@swag_from("swagger_docs/user_assign_role.yml")
def assign_role():
    try:
        data = request.get_json()
        validated_data = UserRoleAssignmentRequest(**data)
    except ValidationError as e:
        return jsonify(error_response(f"Invalid request data: {e.errors()}")), 400

    user_id = validated_data.user_id
    role_id = validated_data.role_id

    user = User.query.get(user_id)
    role = Role.query.get(role_id)

    if not user or not role:
        return jsonify(error_response("Invalid user or role ID")), 400

    mapping = UserRoleMapping(user_id=user_id, role_id=role_id)
    db.session.add(mapping)
    db.session.commit()

    return jsonify(success_response("Role assigned successfully", {"user_id": user_id, "role_id": role_id})), 201
