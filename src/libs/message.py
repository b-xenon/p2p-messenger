from enum import Enum
from pydantic import BaseModel
from typing import Literal, Union

from config import FilenameType

MessageIdType = str
ISO_FormatData = str

class MessageType(Enum):
    Text = 'Text'
    File = 'File'

class MessageTextData(BaseModel):
    id: MessageIdType
    time: ISO_FormatData
    author: str
    message: str

class MessageFileData(BaseModel):
    raw_data: str
    filename: FilenameType

class MessageData(BaseModel):
    type: MessageType
    message: Union[MessageTextData, MessageFileData, MessageIdType, FilenameType]
