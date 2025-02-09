from pydantic import BaseModel

class PermissionCreateRequest(BaseModel):
    permission_name: str
