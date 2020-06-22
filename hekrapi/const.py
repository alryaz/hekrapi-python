# -*- coding: utf-8 -*-
# pylint: disable=too-many-locals
"""Global constants and enums for HekrAPI module"""

from enum import Enum


class FrameType(Enum):
    """Datagram frame types (per Hekr documentation)"""
    RECEIVE = 0x01
    SEND = 0x02
    DEVICE = 0xFE
    ERROR = 0xFF


#: Device response states
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


class DeviceConnectionType(Enum):
    LOCAL = 1
    CLOUD = 2


#: Default application ID used within requests via cloud and local transports
DEFAULT_APPLICATION_ID = 'hekr_python_connector'
DEFAULT_APPLICATION_NAME = 'hekr_python_connector'
DEFAULT_APPLICATION_VERSION = '1.0.0.0'
DEFAULT_APPLICATION_TYPE = 'hekr'
DEFAULT_OS_VERSION = 9

#: First character of every presumably valid raw datagram
FRAME_START_IDENTIFICATION = 0x48

#: Default port to send UDP datagrams to
DEFAULT_DEVICE_PORT = 10000

#: Default amount of attempts a request should retry doing itself
DEFAULT_REQUEST_RETRIES = 2

#: Seconds count before attempting to perform next request iteration
DEFAULT_RETRY_DELAY = 1

#: Default host for controlling devices via websocket
DEFAULT_WEBSOCKET_HOST = 'fra-hub.hekreu.me'
DEFAULT_WEBSOCKET_PORT = 186

#: Default connection timeout
DEFAULT_TIMEOUT = 10.0

#: Device actions in requests/responses
ACTION_DEVICE_AUTH_REQUEST = 'appDevAuth'
ACTION_DEVICE_AUTH_RESPONSE = 'appDevAuthResp'
ACTION_CLOUD_AUTH_REQUEST = 'appLogin'
ACTION_CLOUD_AUTH_RESPONSE = 'appLoginResp'
ACTION_HEARTBEAT_REQUEST = 'heartbeat'
ACTION_HEARTBEAT_RESPONSE = 'heartbeatResp'
ACTION_COMMAND_REQUEST = 'appSend'
ACTION_COMMAND_RESPONSE = 'appSendResp'
ACTION_DEVICE_MESSAGE = 'devSend'
