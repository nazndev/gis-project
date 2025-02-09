from flask import request, jsonify
from flask_jwt_extended import jwt_required
from app.services.role_service import create_role, get_roles
from app.utils.response_util import success_response, error_response
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError
from app.schemas.role_schema import RoleCreateRequest

@jwt_required()
def add_role():
    try:
        data = request.get_json()
        validated_data = RoleCreateRequest(**data)
    except ValidationError as e:
        return jsonify(error_response(f"Invalid request data: {e.errors()}")), 400

    try:
        role = create_role(validated_data.role_name)
        if not role:
            return jsonify(error_response("Role already exists")), 400
        return jsonify(success_response("Role created successfully", {"role_id": role.id, "role_name": role.name})), 201
    except Exception as e:
        return jsonify(error_response(f"Unexpected error: {str(e)}", 500)), 500

@jwt_required()
def list_roles():
    try:
        roles = get_roles()
        return jsonify(success_response("Roles retrieved successfully", roles)), 200
    except Exception as e:
        return jsonify(error_response(f"Unexpected error: {str(e)}", 500)), 500
