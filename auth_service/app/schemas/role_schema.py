from pydantic import BaseModel

class RoleCreateRequest(BaseModel):
    role_name: str
