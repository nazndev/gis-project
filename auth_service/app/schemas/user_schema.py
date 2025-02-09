from pydantic import BaseModel, EmailStr

class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str

class UserRoleAssignmentRequest(BaseModel):
    user_id: int
    role_id: int
