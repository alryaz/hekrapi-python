"""Types for Hekr API project."""

from typing import Tuple, Dict, Any, Union, Optional, Callable, TypeVar, TYPE_CHECKING

from .const import DeviceResponseState

if TYPE_CHECKING:
    # noinspection PyUnresolvedReferences
    from .device import Device, Response
    # noinspection PyUnresolvedReferences
    from .protocol import Command

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

DeviceCallback = Callable[['Response'], Any]

DeviceInfo = Dict[str, Any]

# Helper types
AnyCommand = Union[CommandID, CommandName, 'Command']
