from pydantic import BaseModel
from typing import Literal, Union

class MessageType(BaseModel):
    type: Literal['Text', 'File']

class MessageTextData(BaseModel):
    id: str
    time: str
    author: str
    message: str

class MessageFileData(BaseModel):
    raw_data: str
    filename: str

class MessageData(BaseModel):
    type: MessageType
    message: Union[MessageTextData, MessageFileData]
