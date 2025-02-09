from flask import request, jsonify
from app.services.permission_service import create_permission, get_permissions
from app.utils.response_util import success_response, error_response
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError
from app.schemas.permission_schema import PermissionCreateRequest
from flasgger import swag_from

@swag_from("swagger_docs/permission_add.yml")
def add_permission():
    try:
        data = request.get_json()
        validated_data = PermissionCreateRequest(**data)
    except ValidationError as e:
        return jsonify(error_response(f"Invalid request data: {e.errors()}")), 400

    try:
        permission = create_permission(validated_data.permission_name)
        return jsonify(success_response("Permission created successfully",
                                        {"permission_id": permission.id, "permission_name": permission.name})), 201
    except IntegrityError:
        return jsonify(error_response("Permission already exists")), 400

@swag_from("swagger_docs/permission_list.yml")
def list_permissions():
    permissions = get_permissions()
    return jsonify(success_response("Permissions fetched successfully", permissions)), 200
