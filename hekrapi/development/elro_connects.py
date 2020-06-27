# -*- coding: utf-8 -*-
"""Basic protocol definition for ELRO Connects"""
from enum import auto, Enum, Flag

from hekrapi.exceptions import HekrAPIException
from typing import TYPE_CHECKING, NamedTuple, Union, Optional

from hekrapi.connector import LocalConnector, _LocalEndpointConnector

from hekrapi.protocol import Protocol, Encoding, Command, Argument, register_supported_protocol
from hekrapi.enums import FrameType, DeviceResponseState

try:
    from typing import NoReturn
except ImportError:
    NoReturn = None

if TYPE_CHECKING:
    from hekrapi.connector import Response

__all__ = [
    'ELROConnectsProtocol',
    'CMD_SCENE_GROUP_SELECT',
]

CMD_SCENE_GROUP_SELECT = "scene_group_select"

ARG_EQUIPMENT_ID = "equipment_id"
ARG_STATE = "state"
ARG_NAME = "name"
ARG_GROUP = "group"

ARGUMENT_EQUIPMENT_ID = Argument(ARG_EQUIPMENT_ID, int, None, "device_ID")
ARGUMENT_SCENE_GROUP = Argument(ARG_GROUP, int, None, "scene_type", value_default=0)


class GenericType(Enum):
    """Enumeration of generic types"""
    # Unknown device from code (used when code is not found in `CODE_TO_GENERIC_TYPE` dictionary)
    UNKNOWN = auto()

    # Extracted standard device types
    DOOR_CHECK = auto()
    SOCKET = auto()
    SOS_KEY = auto()
    PIR_CHECK = auto()
    CO_ALARM = auto()
    GAS_ALARM = auto()
    SM_ALARM = auto()
    WT_ALARM = auto()
    TH_CHECK = auto()
    LAMP = auto()
    GUARD = auto()
    VALVE = auto()
    BUTTON = auto()
    CURTAIN = auto()
    CXSM_ALARM = auto()
    THERMAL_ALARM = auto()
    MODE_BUTTON = auto()
    LOCK = auto()
    TWO_SOCKET = auto()
    TEMP_CONTROL = auto()
    DIMMING_MODULE = auto()


# Match generic types to codes
GENERIC_TYPE_TO_CODES = {
    GenericType.DOOR_CHECK: ("0101", "1101", "2101"),
    GenericType.SOCKET: ("0200", "1200", "2200"),
    GenericType.SOS_KEY: ("0300", "1300", "2300"),
    GenericType.PIR_CHECK: ("0100", "1100", "2100"),
    GenericType.CO_ALARM: ("0000", "1000", "2000", "0008", "1008", "2008", "000E", "100E", "200E"),
    GenericType.GAS_ALARM: ("0002", "1002", "2002", "1006", "000A", "100A", "200A", "0010", "1010", "2010"),
    GenericType.SM_ALARM: ("0001", "1001", "2001", "0009", "1009", "2009", "000F", "100F", "200F"),
    GenericType.WT_ALARM: ("0004", "1004", "2004", "000C", "100C", "200C", "0012", "1012", "2012"),
    GenericType.TH_CHECK: ("0102", "1102", "2102"),
    GenericType.LAMP: ("020A", "120A", "220A"),
    GenericType.GUARD: ("0210", "1210", "2210"),
    GenericType.VALVE: ("0208", "1208", "2208"),
    GenericType.BUTTON: ("0301", "1301", "2301"),
    GenericType.CURTAIN: ("0209", "1209", "2209"),
    GenericType.CXSM_ALARM: ("0005", "1109", "2109", "000D", "100D", "200D", "0013", "1013", "2013"),
    GenericType.THERMAL_ALARM: ("0003", "1003", "2003", "000B", "100B", "200B", "0011", "1011", "2011"),
    GenericType.MODE_BUTTON: ("0305",),
    GenericType.LOCK: ("1213",),
    GenericType.TWO_SOCKET: ("0201", "1201", "2201"),
    GenericType.TEMP_CONTROL: ("0215", "1215", "2215"),
    GenericType.DIMMING_MODULE: ("0214", "1214", "2214"),
}

# Match codes to generic types
CODE_TO_GENERIC_TYPE = {
    code: device_type
    for device_type, codes in GENERIC_TYPE_TO_CODES.items()
    for code in codes
}


class ConvertedDeviceType(NamedTuple):
    """Converted device type holder"""
    type: GenericType
    code: str


def from_device_type(type_code: str) -> ConvertedDeviceType:
    """
    Convert type code to a converted device type.
    :param type_code: Device code received from status update
    :return: Converted device type object
    """
    return ConvertedDeviceType(
        type=CODE_TO_GENERIC_TYPE.get(type_code, GenericType.UNKNOWN),
        code=type_code
    )


def to_device_type(generic_type: Union[GenericType, ConvertedDeviceType],
                   type_code: Optional[Union[bool, str]] = None) -> str:
    """
    Convert device type object to device type code.
    :param generic_type: Device type object / Generic type
    :param type_code: Type code; True for fetching the first code from `GENERIC_TYPE_TO_CODES`
                      matching to generic_type (unless generic_type is a generic type object)
    :return: Type code
    """
    if isinstance(generic_type, ConvertedDeviceType):
        if type_code is not None:
            raise ValueError('type_code cannot be set along with a tuple generic_type')
        return generic_type.code
    if type_code is True:
        type_code = GENERIC_TYPE_TO_CODES[generic_type][0]
    if type_code is None:
        raise ValueError('type_code cannot be omitted when providing a generic type')
    return type_code


DEVICE_TYPE_CONVERTER = (from_device_type, to_device_type)


class ELROLocalConnector(_LocalEndpointConnector):

    async def _internal_authenticate(self) -> NoReturn:
        device = self.attached_device
        if device is None:
            raise HekrAPIException('No devices attached to connector (required to perform authentication)')
        await self._internal_send_request('IOT_KEY?%s:LIDL01EN' % device.device_id)
        # @TODO: more checks to ensure authentication
        self._authenticated = True

    def process_response(self, response_str: str) -> 'Response':
        if any(map(lambda x: x in response_str, ['answer_yes_or_no', 'ST_answer_OK'])):
            return Response(
                original=response_str,
                state=DeviceResponseState.SUCCESS,
                # device=self.attached_device
            )

        response = super(ELROLocalConnector, self).process_response(response_str)

        if response.state == DeviceResponseState.UNKNOWN:
            pass

        return response

    async def _acknowledge_response(self, response: 'Response') -> NoReturn:
        await self._internal_send_request('{"answer": "APP_answer_OK"}')


@register_supported_protocol
class ELROConnectsProtocol(Protocol):
    default_encoding_type = Encoding.JSON
    default_local_connector_class = ELROLocalConnector

    # Data receiving

    # Equipment-related commands
    equipment_control = Command(1, FrameType.SEND, arguments=[
        ARGUMENT_EQUIPMENT_ID, Argument("state", str, None, "device_status"),
    ], description="Control equipment by sending status")
    equipment_add = Command(2, FrameType.SEND),
    equipment_replace = Command(3, FrameType.SEND, arguments=[ARGUMENT_EQUIPMENT_ID])
    equipment_remove = Command(4, FrameType.SEND, arguments=[ARGUMENT_EQUIPMENT_ID])
    equipment_rename = Command(5, FrameType.SEND, arguments=[
        ARGUMENT_EQUIPMENT_ID,
        Argument("name", str, None, "device_name"),
    ])

    # Scene-related commands
    scene_add = Command(8, FrameType.SEND, arguments=[ARGUMENT_SCENE_GROUP])  # @TODO: finish this command
    scene_modify = Command(9, FrameType.SEND)  # @TODO: finish this command
    scene_remove = Command(10, FrameType.SEND)  # @TODO: finish this command
    query_scene_status = Command(18, FrameType.SEND),  # @TODO: finish this command
    report_scene_status = Command(26, FrameType.RECEIVE),  # @TODO: finish this command

    scene_group_add = Command(23, FrameType.SEND),  # @TODO: finish this command
    scene_group_modify = Command(24, FrameType.SEND),  # @TODO: finish this command
    scene_group_select = Command(6, FrameType.SEND, arguments=[ARGUMENT_SCENE_GROUP]),

    # Equipment status updates
    query_equipment_status = Command(15, FrameType.SEND, response_command_id=19)  # @TODO: finish this command
    report_equipment_status = Command(19, FrameType.RECEIVE, arguments=[
        Argument("device_id", int, None, "device_ID"),
        Argument("device_type", DEVICE_TYPE_CONVERTER, None, "device_name"),
        Argument("device_status", )
    ])  # @TODO: finish this command
    equipment_cancel_remove = Command(7, FrameType.SEND)

    # Device-related commands
    query_device_name = Command(14, FrameType.SEND)  # @TODO: finish this command
    time_check = Command(21, FrameType.SEND)  # @TODO: finish this command

    # Device alarm triggers
    report_device_alarm = Command(25, FrameType.RECEIVE,
                                  description='Sent by device when an alarm has been triggered')  # @TODO: finish this command

    # commands 11-13 ?
    # command 16 ?
    # command 17 ?
    # command 27 ?
    # command 28 ?
    sync_device_status = Command(29, FrameType.SEND)  # @TODO: finish this command
    sync_device_name = Command(30, FrameType.SEND)  # @TODO: finish this command
    sync_scene = Command(31, FrameType.SEND)  # @TODO: finish this command
    scene_handle = Command(32, FrameType.SEND)  # @TODO: finish this command
    scene_group_delete = Command(33, FrameType.SEND)  # @TODO: finish this command
    model_switch_timer = Command(34, FrameType.SEND)  # @TODO: finish this command
    model_timer_syn = Command(35, FrameType.SEND)  # @TODO: finish this command
    upload_model_timer = Command(36, FrameType.SEND)  # @TODO: finish this command
    delete_group_timer = Command(37, FrameType.SEND)  # @TODO: finish this command
    # commands 38-100 ?


    # commands 107-250 ?
    send_timezone = Command(251, FrameType.SEND)  # @TODO: finish this command
    # commands 252-255 ?
