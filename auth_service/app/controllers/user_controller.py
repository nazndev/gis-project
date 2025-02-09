from flask import request, jsonify
from flask_jwt_extended import jwt_required
from flasgger import swag_from
from pydantic import ValidationError

from app import db
from app.models.role_model import Role, user_role_mapping  # Ensure correct import
from app.models.user_model import User
from app.services.user_service import create_user, get_user_by_email
from app.utils.response_util import success_response, error_response
from app.schemas.user_schema import UserRegisterRequest, UserRoleAssignmentRequest

@swag_from("swagger_docs/user_register.yml")
def register_user():
    """Register a new user."""
    try:
        data = request.get_json()
        validated_data = UserRegisterRequest(**data)
    except ValidationError as e:
        return jsonify(error_response(f"Invalid request data: {e.errors()}")), 400

    user, error = create_user(validated_data.email, validated_data.password)
    if error:
        return jsonify(error_response(error)), 400

    return jsonify(success_response("User registered successfully", {"user_id": user.id, "email": user.email})), 201


@jwt_required()
@swag_from("swagger_docs/user_get.yml")
def get_user():
    """Get user details (Protected API)."""
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
    """Assign a role to a user."""
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

    # Check if the user already has the role
    if role in user.roles:
        return jsonify(error_response("User already has this role assigned")), 400

    # Assign the role
    user.roles.append(role)
    db.session.commit()

    return jsonify(success_response("Role assigned successfully", {"user_id": user_id, "role_id": role_id})), 201
