# -*- coding: utf-8 -*-
"""Device class module for Hekr API"""
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
    CloudAuthenticationFailedException,
    CommandFailedException,
    DeviceConnectionMissingException,
    AuthenticationFailedException
)
from .const import (
    DEFAULT_APPLICATION_ID,
    ACTION_AUTHENTICATE,
    DEFAULT_DEVICE_PORT
)


def device_id_from_mac_address(mac_address: Union[str, bytearray]) -> str:
    """Convert mac address to device ID

    Arguments:
        mac_address {Union[str, bytearray]} -- MAC-address string (dashed format)

    Returns:
        str -- Device ID
    """
    if isinstance(mac_address, bytearray):
        mac_address = mac_address.hex()

    for delimiter in [':', '-', ' ']:
        mac_address = mac_address.replace(delimiter, '')

    mac_address = mac_address.upper()
    return 'ESP_2M_' + mac_address


class DeviceConnectionType(IntEnum):
    """Connection types for devices"""
    NONE = 0
    LOCAL = 1
    CLOUD = 2


class Device:
    """Device class for Hekr API"""

    def __init__(self,
                 device_id: str,
                 control_key: str,
                 account: Union['Account', type(None)]=None,
                 host: Union[str, type(None)]=None,
                 port: int = DEFAULT_DEVICE_PORT,
                 application_id: str = DEFAULT_APPLICATION_ID,
                 protocol: Union['Protocol', type(None)]=None
                 ):
        self.device_id = device_id
        self.local_address = (host, port)
        self.account = account
        self.protocol = protocol
        self.application_id = application_id
        self.local_socket = None

        self.local_message_id = 0

        self.__local_authenticated = False
        self.__control_key = control_key

    @property
    def available_connection_type(self) -> DeviceConnectionType:
        """Retrieve best available connection type for communication

        Returns:
            DeviceConnectionType -- Available connection type
        """
        # @TODO: check for more stuff to determine connection type
        if self.local_address and self.__control_key:
            return DeviceConnectionType.LOCAL
        if self.account:
            return DeviceConnectionType.CLOUD

        return DeviceConnectionType.NONE

    def set_control_key(self, control_key: str):
        """Sets device control key

        Arguments:
            control_key {str} -- Control key
        """
        self.__control_key = control_key

    def open_socket_local(self):
        """Opens local socket to device"""
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.connect(self.local_address)
        sock.settimeout(5)
        # sock.setblocking(0)
        self.local_socket = sock

    def make_request(self, action: str, params: dict = None,
                     message_id: int = None,
                     frame_number: int = None,
                     connection_type: DeviceConnectionType = None):
        """Make device request

        Arguments:
            action {str} -- Action string

        Keyword Arguments:
            params {dict} -- Request parameters (default: {None})
            message_id {int} -- Message ID (default: {None})
            frame_number {int} -- Frame number (default: {None})
            connection_type {DeviceConnectionType} -- Connection type (default: {None})

        Returns:
            dict -- Request response
        """
        connection_type = connection_type or self.available_connection_type

        if connection_type == DeviceConnectionType.LOCAL:
            # @TODO: message IDs should be carried across all instances by definition
            if not self.__local_authenticated and action != ACTION_AUTHENTICATE:
                self.authenticate(connection_type=DeviceConnectionType.LOCAL)

            if self.local_socket is None:
                self.open_socket_local()

            if message_id is None:
                self.local_message_id += 1
                message_id = self.local_message_id

            if frame_number is None:
                frame_number = 1

            request_dict = {
                "msgId": message_id,
                "action": action,
                "params": {
                    "ctrlKey": self.__control_key,
                    "devTid": self.device_id
                }
            }
            if params:
                request_dict["params"].update(params)

            self.local_socket.send(dumps(request_dict).encode('utf-8'))

            return self.read_response(connection_type=connection_type)

        if connection_type == DeviceConnectionType.CLOUD:
            # @TODO: not implemented
            return False

        raise DeviceConnectionMissingException(self)

    def read_response(self, length: int = 256, connection_type: DeviceConnectionType = None):
        """Read device response

        Keyword Arguments:
            length {int} -- Message length to expect (default: {256})
            connection_type {DeviceConnectionType} -- Connection type to use (default: {None})

        Returns:
            dict -- JSON-decoded dictionary of values
        """
        connection_type = connection_type or self.available_connection_type

        if connection_type == DeviceConnectionType.LOCAL:
            received_data = self.local_socket.recv(length)

            # @TODO: exceptions for nothingness
            return loads(received_data)

        if connection_type == DeviceConnectionType.CLOUD:
            # @TODO: not implemented
            pass

        return DeviceConnectionMissingException(self)

    def heartbeat(self, connection_type: DeviceConnectionType = None):
        """Send heartbeat message

        Keyword Arguments:
            connection_type {DeviceConnectionType} -- Connection type to use (default: {None})

        Raises:
            HeartbeatFailedException: Heartbeat message sending failed
        """
        response = self.make_request(
            action='heartbeat',
            params=False,
            connection_type=connection_type)

        if response.get("code", None) != 200:
            raise HeartbeatFailedException(self, response)

    def command(self,
                command: Union[int, str, Command],
                data: dict = None,
                return_decoded=True):
        """Execute device command and return response

        Arguments:
            command {Union[int, str, Command]} -- Command ID/name/object to use

        Keyword Arguments:
            data {dict} -- Data values for datagram (default: {None})
            return_decoded {bool} -- Extract and decode datagram from response (default: {True})

        Raises:
            DeviceProtocolNotSetException: Device does not have a protocol set
            CommandFailedException: Command failed to execute due to device code error
            CommandFailedException: Command failed to execute due to missing datagram
            CommandFailedException: Command failed to execute due to socket timeout

        Returns:
            dict -- decoded datagram values or full response dictionary
        """
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
            raise CommandFailedException(command=command, protocol=self, response=response)

        try:
            response = self.read_response(512)

            if return_decoded:
                datagram = (response
                            .get('params', {})
                            .get('data', {})
                            .get('raw', None)
                            )

                if not datagram:
                    raise CommandFailedException(
                        command=command, protocol=self, response=response,
                        reason='Datagram not found')

                return self.protocol.decode(datagram)

            return response

        except SocketTimeout:
            raise CommandFailedException(
                command=command, protocol=self, response=response,
                reason='Socket timeout')

    def authenticate(self, connection_type: DeviceConnectionType = None):
        """Authenticate with the device

        Keyword Arguments:
            connection_type {DeviceConnectionType} -- Connection type to use (default: {None})

        Raises:
            LocalAuthenticationFailedException: Local authentication failed
            AuthenticationFailedException: Authentication failed
        """
        connection_type = connection_type or self.available_connection_type

        if connection_type == DeviceConnectionType.LOCAL:
            response = self.make_request(
                action=ACTION_AUTHENTICATE,
                connection_type=connection_type)

            if response.get("code", None) != 200:
                raise LocalAuthenticationFailedException(self, response)

            self.__local_authenticated = True
            return True

        elif connection_type == DeviceConnectionType.CLOUD:
            raise CloudAuthenticationFailedException(self)

        # @TODO: research into authentication
        raise AuthenticationFailedException(self)
