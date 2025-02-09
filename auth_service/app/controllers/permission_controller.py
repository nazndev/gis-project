from flask import request, jsonify
from flask_jwt_extended import jwt_required
from app.services.permission_service import create_permission, get_permissions
from app.utils.response_util import success_response, error_response
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError
from app.schemas.permission_schema import PermissionCreateRequest

@jwt_required()
def add_permission():
    """Create a new permission."""
    try:
        data = request.get_json()
        validated_data = PermissionCreateRequest(**data)
    except ValidationError as e:
        return jsonify(error_response(f"Invalid request data: {e.errors()}")), 400

    permission, error = create_permission(validated_data.permission_name)
    if error:
        return jsonify(error_response(error)), 400

    return jsonify(success_response("Permission created successfully",
                                    {"permission_id": permission.id, "permission_name": permission.name})), 201

@jwt_required()
def list_permissions():
    try:
        permissions = get_permissions()
        return jsonify(success_response("Permissions retrieved successfully", permissions)), 200
    except Exception as e:
        return jsonify(error_response(f"Unexpected error: {str(e)}", 500)), 500
