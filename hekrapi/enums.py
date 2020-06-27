"""Global enums for HekrAPI module"""
from enum import Enum, Flag, auto


class FrameType(Enum):
    """Datagram frame types (per Hekr documentation)"""
    RECEIVE = 0x01
    SEND = 0x02
    DEVICE = 0xFE
    ERROR = 0xFF


class DeviceResponseState(Enum):
    """
    Response state of `make_request`

    Glossary:
    _Invalid_ responses are of a format that can't be loaded by `process_response` methods.
    _Unknown_ responses are parsed responses that have no associated command or action.
    _Successful_ responses are decoded responses that translate into successful request execution.
    _Failed_ responses are decoded responses that translate into failed (not invalid!) request execution.
    """
    INVALID = -1
    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2


class WorkMode(Enum):
    """Device communication mode"""
    CONTROL = "JSON_CTRL"
    TRANSPARENT = "JSON_TRANSPARENT"
    JSON_NO_RAW = "JSON_TRANSPARENT_NO_CHECK_RAW"


class DeviceType(Enum):
    """Device type"""
    INDEPENDENT = "INDEPENDENT"
    GATEWAY = "GATEWAY"
    SUB = "SUB"


class Encoding(Flag):
    """Encoding for protocols"""
    JSON = auto()
    RAW = auto()
