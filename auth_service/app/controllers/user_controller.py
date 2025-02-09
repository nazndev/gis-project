from flask import request, jsonify
from app.services.user_service import create_user, get_user_by_email
from app.utils.response_util import success_response, error_response
from flask_jwt_extended import jwt_required
from pydantic import ValidationError
from app.schemas.user_schema import UserRegisterRequest, UserRoleAssignmentRequest
from app.models.user_role_mapping import UserRoleMapping, db
from app.models.user_model import User
from app.models.role_model import Role


@jwt_required()
def get_user():
    email = request.args.get("email")
    if not email:
        return jsonify(error_response("Email is required")), 400

    user = get_user_by_email(email)
    if not user:
        return jsonify(error_response("User not found")), 404

    return jsonify(success_response("User found", {"user_id": user.id, "email": user.email})), 200

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
def assign_role():
    """Assign a role to a user."""
    try:
        data = request.get_json()
        validated_data = UserRoleAssignmentRequest(**data)
    except ValidationError as e:
        return jsonify(error_response(f"Invalid request data: {e.errors()}")), 400

    user = User.query.get(validated_data.user_id)
    role = Role.query.get(validated_data.role_id)

    if not user:
        return jsonify(error_response("User not found")), 404
    if not role:
        return jsonify(error_response("Role not found")), 404

    existing_mapping = UserRoleMapping.query.filter_by(user_id=user.id, role_id=role.id).first()
    if existing_mapping:
        return jsonify(error_response("User already assigned this role")), 400

    mapping = UserRoleMapping(user_id=user.id, role_id=role.id)
    db.session.add(mapping)
    db.session.commit()

    return jsonify(success_response("Role assigned successfully", {"user_id": user.id, "role_id": role.id})), 201
