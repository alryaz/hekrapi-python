"""Types for Hekr API project."""

from typing import Tuple, Dict, Any, Union, Optional, Callable, TypeVar

from .const import DeviceResponseState

# Raw datagram type
RawDataType = Union[str, bytes, bytearray]
JSONDataType = Dict[str, Optional[Union[str, int]]]

# Encoding / decoding types
CommandData = Dict[str, Any]
MessageData = Dict[str, Union[str, int, float]]

DecodeResult = Tuple['Command', CommandData, int]
MessageID = int
DeviceID = str
Action = str

ProcessedData = Union[dict, DecodeResult]
DeviceResponse = Tuple[MessageID, DeviceResponseState, Action, ProcessedData]
ProcessedResponse = Tuple[MessageID, DeviceResponseState, Action, ProcessedData, Optional['Device']]

HekrCallback = Callable[[Optional['Device'], MessageID, DeviceResponseState, Action, ProcessedData], Any]

DeviceInfo = Dict[str, Any]
AnyCommand = Union[int, str, 'Command']
MessageEncoded = TypeVar('MessageEncoded')
CommandEncoded = TypeVar('CommandEncoded')
DevicesDict = Dict[DeviceID, 'Device']
