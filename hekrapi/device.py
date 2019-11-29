from typing import Union

from enum import IntEnum
from socket import (
    socket, AF_INET, SOCK_DGRAM,
    timeout as SocketTimeout
)
from json import (dumps, loads)

from .command import Command
from .exceptions import (
    DeviceProtocolNotSetException,
    HeartbeatFailedException,
    LocalAuthenticationFailedException,
    CommandFailedException
)
from .const import (
    DEFAULT_APPLICATION_ID, ACTION_AUTHENTICATE
)


def device_id_from_mac_address(mac_address: Union[str, bytearray]):
    if isinstance(mac_address, bytearray):
        mac_address = mac_address.hex()

    for ch in [':', '-', ' ']:
        mac_address = mac_address.replace(ch, '')

    mac_address = mac_address.upper()
    return 'ESP_2M_' + mac_address


class DeviceConnectionType(IntEnum):
    NONE = 0
    LOCAL = 1
    CLOUD = 2


class Device(object):
    def __init__(
        self, device_id, control_key,
        account=None,
        host=None, port=10000,
        application_id=DEFAULT_APPLICATION_ID,
        protocol: Union['Protocol', type(None)] = None
    ):
        self.device_id = device_id
        self.host = host
        self.port = port
        self.account = account
        self.application_id = application_id
        self.protocol = protocol
        self.local_socket = None

        self.local_frame_number = 0

        self.__local_authenticated = False
        self.__control_key = control_key

    @property
    def connection_type(self):
        """ Retrieve best connection type for request functions """
        # @TODO: check for more stuff to determine connection type
        if self.host and self.port and self.__control_key:
            return DeviceConnectionType.LOCAL
        elif self.account:
            return DeviceConnectionType.CLOUD
        else:
            return DeviceConnectionType.NONE

    def set_control_key(self, control_key):
        self.__control_key = control_key

    def open_socket_local(self):
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.connect((self.host, self.port))
        sock.settimeout(5)
        # sock.setblocking(0)
        self.local_socket = sock

    def make_request_local(
            self, action: str, params: dict = {}, frame_number: int = None):
        # @TODO: message IDs should be carried across all instances by definition
        if not self.__local_authenticated and action != ACTION_AUTHENTICATE:
            self.authenticate_local()

        if self.local_socket is None:
            self.open_socket_local()

        if frame_number is None:
            self.local_frame_number += 1
            frame_number = self.local_frame_number

        request_dict = {
            "msgId": frame_number,
            "action": action,
        }
        if params:
            request_dict["params"] = {
                "devTid": self.device_id,
                "ctrlKey": self.__control_key
            }
            request_dict["params"].update(params)

        self.local_socket.send(dumps(request_dict).encode('utf-8'))
        return self.read_response_local()

    def read_response_local(self, length: int = 256):
        received_data = self.local_socket.recv(length)
        # @TODO: exceptions for nothingness
        return loads(received_data)

    def make_request_cloud(
            self, action: str, params: dict = {}, message_id: int = None):
        pass

    def read_response_cloud(self, length: int = 256):
        pass

    def make_request(self, action: str, params: dict = {},
                     message_id: int = None):
        if self.connection_type == DeviceConnectionType.LOCAL:
            return self.make_request_local(action=action, params=params)
        elif self.connection_type == DeviceConnectionType.CLOUD:
            return self.make_request_cloud(action=action, params=params)
        elif self.connection_type == DeviceConnectionType.NONE:
            raise Exception(
                'Cannot make requests to device until connection parameters are provided')

    def read_response(self, length: int = 256):
        if self.connection_type == DeviceConnectionType.LOCAL:
            return self.read_response_local(length=length)
        elif self.connection_type == DeviceConnectionType.CLOUD:
            return self.read_response_cloud(length=length)
        elif self.connection_type == DeviceConnectionType.NONE:
            return Exception(
                'Cannot read responses from device until connection parameters are provided')

    def heartbeat(self):
        response = self.make_request(action='heartbeat', params=False)

        if response.get("code", None) != 200:
            raise HeartbeatFailedException(self, response)

    def command(self, command: Union[int, str,
                                     Command], data={}, return_decoded=True):
        if not isinstance(command, Command):
            if self.protocol:
                command = self.protocol.get_command(command)
            else:
                raise DeviceProtocolNotSetException(self)

        raw = self.protocol.encode(
            data=data,
            command=command,
            frame_number=1
        )

        request_dict = {
            "appTid": self.application_id,
            "data": {
                "raw": raw
            }
        }
        response = self.make_request(
            action='appSend',
            params=request_dict
        )

        if response.get("code", None) != 200:
            raise CommandFailedException(command, self, response)

        try:
            response = self.read_response(512)
        except SocketTimeout:
            #_LOGGER.debug('socket timeout for command %s', command)
            return None

        if return_decoded:
            datagram = response.get(
                'params',
                {}).get(
                'data',
                {}).get(
                'raw',
                None)

            if datagram:
                return self.protocol.decode(datagram)
            else:
                raise CommandFailedException(
                    command, self, response, reason='Datagram not found')

        else:
            return response

        # @TODO: warning! difficult to research into data frames, the device works so far like this: send(02)->receive(02)->receive(01)->

    def authenticate_local(self):
        response = self.make_request_local(action=ACTION_AUTHENTICATE)

        if response.get("code", None) != 200:
            #_LOGGER.error('Could not login locally to ' + self.device_id + ", response: " + str(response))
            raise LocalAuthenticationFailedException(self)

        self.__local_authenticated = True

    def authenticate(self):
        if self.connection_type == DeviceConnectionType.LOCAL:
            return self.authenticate_local()
        else:
            # @TODO: research into authentication
            return False
