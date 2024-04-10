from enum import Enum
from typing import Union, NamedTuple
from dataclasses import dataclass

class MessageType(Enum):
    Text = 'Text'
    File = 'File'

@dataclass
class MessageTextData:
    id: str
    time: str
    author: str
    message: str

class MessageFileData(NamedTuple):
    raw_data: str
    filename: str

class MessageData(NamedTuple):
    type: MessageType
    message: Union[MessageTextData, MessageFileData]


m = MessageData(
    type=MessageType.Text.value,
    message=MessageTextData(
        id='m0',
        time='10.01.2000',
        author='oleg',
        message='hello world!'
    )
)
