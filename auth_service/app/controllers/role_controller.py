from flask import request, jsonify
from app.services.role_service import create_role, get_roles
from app.utils.response_util import success_response, error_response
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError
from app.schemas.role_schema import RoleCreateRequest
from flasgger import swag_from

@swag_from("swagger_docs/role_add.yml")
def add_role():
    try:
        data = request.get_json()
        validated_data = RoleCreateRequest(**data)
    except ValidationError as e:
        return jsonify(error_response(f"Invalid request data: {e.errors()}")), 400

    try:
        role = create_role(validated_data.role_name)
        return jsonify(success_response("Role created successfully", {"role_id": role.id, "role_name": role.name})), 201
    except IntegrityError:
        return jsonify(error_response("Role already exists")), 400

@swag_from("swagger_docs/role_list.yml")
def list_roles():
    roles = get_roles()
    return jsonify(success_response("Roles fetched successfully", roles)), 200
