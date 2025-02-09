from pydantic import BaseModel

class AuthCallbackRequest(BaseModel):
    code: str

class TokenExchangeRequest(BaseModel):
    code: str