"""Types for Hekr API project."""

from typing import Tuple, Dict, Any, Union, Optional, Callable, TYPE_CHECKING

from .const import DeviceResponseState

if TYPE_CHECKING:
    # noinspection PyUnresolvedReferences
    from .command import Command
    # noinspection PyUnresolvedReferences
    from .device import Device

DecodeResult = Tuple['Command', Dict[str, Any], int]
MessageID = int
DeviceID = str
Action = str

ProcessedData = Union[dict, DecodeResult]
DeviceResponse = Tuple[MessageID, DeviceResponseState, Action, ProcessedData]
ProcessedResponse = Tuple[MessageID, DeviceResponseState, Action, ProcessedData, Optional['Device']]

HekrCallback = Callable[[Optional['Device'], MessageID, DeviceResponseState, Action, ProcessedData], Any]

DeviceInfo = Dict[str, Any]
AnyCommand = Union[int, str, 'Command']
CommandData = Optional[Dict[str, Any]]
DevicesDict = Dict[DeviceID, 'Device']
