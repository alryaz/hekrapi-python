# -*- coding: utf-8 -*-
# pylint: disable=too-many-locals
"""Global constants for HekrAPI module"""

#: Default application ID used within requests via cloud and local transports
DEFAULT_APPLICATION_ID = 'hekr_python_connector'

#: First character of every presumably valid raw datagram
FRAME_START_IDENTIFICATION = 0x48

#: Default port to send UDP datagrams to
DEFAULT_DEVICE_PORT = 10000

#: Default amount of attempts a request should retry doing itself
DEFAULT_REQUEST_RETRIES = 2

#: Seconds count before attempting to perform next request iteration
DEFAULT_RETRY_DELAY = 1

#: Default host for controlling devices via websockets
DEFAULT_WEBSOCKET_HOST = 'fra-hub.hekreu.me'