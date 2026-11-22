from pydantic import BaseModel, ConfigDict, Field


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=128)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class DocumentIn(BaseModel):
    # extra="forbid" rechaza campos inesperados (p. ej. owner_id enviado por el cliente).
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=100)
    content: str = Field(default="", max_length=2000)


class DocumentOut(BaseModel):
    id: int
    owner_id: int
    title: str
    content: str
