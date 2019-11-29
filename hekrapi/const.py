# -*- coding: utf-8 -*-
# pylint: disable=too-many-locals
"""Global constants for HekrAPI module"""

#: Default application ID used within requests via cloud and local transports
DEFAULT_APPLICATION_ID = 'hekr_python_connector'

#: Authentication action name for Account and Device authentication requests
ACTION_AUTHENTICATE = 'appDevAuth'

#: First character of every presumably valid raw datagram
FRAME_START_IDENTIFICATION = 0x48

#: Default port to send UDP datagrams to
DEFAULT_DEVICE_PORT = 10000
