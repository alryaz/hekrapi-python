"""Types for Hekr API project."""

from typing import Dict, Any, Union, Optional, Callable, TypeVar, TYPE_CHECKING, Awaitable

if TYPE_CHECKING:
    # noinspection PyUnresolvedReferences
    from .device import Device
    # noinspection PyUnresolvedReferences
    from .protocol import Command
    # noinspection PyUnresolvedReferences
    from .connector import BaseConnector, Response

# Raw datagram type
RawDataType = Union[str, bytes, bytearray]
JSONDataType = Dict[str, Optional[Union[str, int]]]

# Encoding / decoding types
CommandData = Dict[str, Any]
MessageData = Dict[str, Union[str, int, float]]

MessageEncoded = TypeVar('MessageEncoded')
CommandEncoded = TypeVar('CommandEncoded')

EncodedRequest = str
MessageID = int
DeviceID = str
Action = str
CommandID = int
CommandName = str

ResponseCallback = Callable[['Response'], Any]

DeviceInfo = Dict[str, Any]

# Helper types
AnyCommand = Union[CommandID, CommandName, 'Command']
ListenerErrorCallback = Callable[['_BaseConnector', BaseException], Union[bool, Awaitable[bool]]]
