# -*- coding: utf-8 -*-
"""Device class module for Hekr API"""
from typing import Union
import asyncio
import logging

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
    DEFAULT_DEVICE_PORT,
    DEFAULT_REQUEST_RETRIES,
    DEFAULT_RETRY_DELAY
)

_LOGGER = logging.getLogger(__name__)


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

    def __repr__(self):
        return '<{}({}, {})>'.format(
            self.__class__.__name__,
            self.device_id,
            ':'.join(map(str,self.local_address))
                if self.available_connection_type == DeviceConnectionType.LOCAL
                else self.account
                if self.available_connection_type == DeviceConnectionType.CLOUD
                else DeviceConnectionType.NONE.name
        )

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
        _LOGGER.debug('Opening local socket on device %s', self)
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.connect(self.local_address)
        sock.settimeout(5)
        # sock.setblocking(0)
        self.local_socket = sock

    async def make_request(self, action: str, params: dict = None,
                     message_id: int = None,
                     frame_number: int = None,
                     connection_type: DeviceConnectionType = None,
                     retries:int = DEFAULT_REQUEST_RETRIES):
        """Make device request

        Arguments:
            action {str} -- Action string

        Keyword Arguments:
            params {dict} -- Request parameters (default: {None})
            message_id {int} -- Message ID (default: {None})
            frame_number {int} -- Frame number (default: {None})
            connection_type {DeviceConnectionType} -- Connection type (default: {None})
            retries {int} -- Amount of attempts the request should be made after it fails

        Returns:
            dict -- Request response
        """
        connection_type = connection_type or self.available_connection_type

        if connection_type == DeviceConnectionType.LOCAL:
            _LOGGER.debug('Sending local request to device %s', self)
            # @TODO: message IDs should be carried across all instances by definition
            if not self.__local_authenticated and action != ACTION_AUTHENTICATE:
                _LOGGER.debug('Authenticating before requesting on device %s', self)
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

            _LOGGER.debug('Composed request parameters for device %s, message id %d, params: %s', self, message_id, params)

            _LOGGER.debug('Sending request to local socket on device %s, message id %d', self, message_id)

            self.local_socket.send(dumps(request_dict).encode('utf-8'))

            _LOGGER.debug('Request sent to local socket on device %s, message id %d', self, message_id)

            # @TODO: implement retries functionality
            return message_id

        if connection_type == DeviceConnectionType.CLOUD:
            # @TODO: not implemented
            return {}

        raise DeviceConnectionMissingException(self)

    async def read_response(self, length: int = 256, connection_type: DeviceConnectionType = None):
        """Read device response

        Keyword Arguments:
            length {int} -- Message length to expect (default: {256})
            connection_type {DeviceConnectionType} -- Connection type to use (default: {None})

        Returns:
            dict -- JSON-decoded dictionary of values
        """
        connection_type = connection_type or self.available_connection_type

        if connection_type == DeviceConnectionType.LOCAL:
            _LOGGER.debug('Reading local response for device %s', self)
            received_data = self.local_socket.recv(length)

            _LOGGER.debug('Received local response for device %s, content: %s', self, received_data)

            # @TODO: exceptions for nothingness
            decoded_content = loads(received_data)

            _LOGGER.debug('Decoded local response for device %s, content: %s', self, decoded_content)

            return decoded_content

        if connection_type == DeviceConnectionType.CLOUD:
            # @TODO: not implemented
            pass

        return DeviceConnectionMissingException(self)

    async def heartbeat(self,
                        connection_type: DeviceConnectionType = None,
                        retries:int = DEFAULT_REQUEST_RETRIES):
        """Send heartbeat message

        Keyword Arguments:
            connection_type {DeviceConnectionType} -- Connection type to use (default: {None})
            retries {int} -- Amount of attempts the request should be made after it fails

        Raises:
            HeartbeatFailedException: Heartbeat message sending failed
        """
        _LOGGER.debug('Requesting heartbeat on device %s', self)
        await self.make_request(
            action='heartbeat',
            params=False,
            connection_type=connection_type,
            retries=retries)

        _LOGGER.debug('Receiving heartbeat response on device %s', self)
        response = await self.read_response(connection_type=connection_type)

        if response.get("code", None) != 200:
            _LOGGER.exception('Heartbeat failed to execute on device %s, response: %s', self, str(response))
            raise HeartbeatFailedException(device=self, response=response)

    async def command(self,
                command: Union[int, str, Command],
                data: dict = None,
                return_decoded=True,
                retries:int=DEFAULT_REQUEST_RETRIES,
                retry_delay:int=DEFAULT_RETRY_DELAY,
                connection_type:DeviceConnectionType=None):
        """Execute device command and return response

        Arguments:
            command {Union[int, str, Command]} -- Command ID/name/object to use

        Keyword Arguments:
            data {dict} -- Data values for datagram (default: {None})
            return_decoded {bool} -- Extract and decode datagram from response (default: {True})
            retries {int} -- Amount of attempts the request should be made after it fails

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

        retry_count = 0
        while True:
            raw = self.protocol.encode(
                data=data,
                command=command,
                frame_number=1+retry_count
            )

            request_dict = {
                "appTid": self.application_id,
                "data": {
                    "raw": raw
                }
            }
            await self.make_request(
                action='appSend',
                params=request_dict,
                retries=retries,
                connection_type=connection_type
            )

            response = await self.read_response(256, connection_type=connection_type)

            if response.get("code", None) == 200:
                try:
                    response = await self.read_response(512, connection_type=connection_type)

                    if return_decoded:
                        datagram = (response
                                    .get('params', {})
                                    .get('data', {})
                                    .get('raw', None)
                                    )

                        if not datagram:
                            raise CommandFailedException(
                                command=command, device=self, response=response,
                                reason='Datagram not found')

                        return self.protocol.decode(datagram)

                    return response

                except SocketTimeout:
                    raise CommandFailedException(
                        command=command, protocol=self, response=response,
                        reason='Socket timeout')

            retry_count += 1
            if retry_count >= retries:
                break

            await asyncio.sleep(DEFAULT_RETRY_DELAY)

        raise CommandFailedException(command=command, device=self, response=response)

    async def authenticate(self, connection_type: DeviceConnectionType = None):
        """Authenticate with the device

        Keyword Arguments:
            connection_type {DeviceConnectionType} -- Connection type to use (default: {None})

        Raises:
            LocalAuthenticationFailedException: Local authentication failed
            AuthenticationFailedException: Authentication failed
        """
        connection_type = connection_type or self.available_connection_type

        if connection_type == DeviceConnectionType.LOCAL:
            await self.make_request(
                action=ACTION_AUTHENTICATE,
                connection_type=connection_type)

            response = await self.read_response(connection_type=connection_type)

            if response.get("code", None) != 200:
                raise LocalAuthenticationFailedException(self, response)

            self.__local_authenticated = True
            return True

        elif connection_type == DeviceConnectionType.CLOUD:
            raise CloudAuthenticationFailedException(self)

        # @TODO: research into authentication
        raise AuthenticationFailedException(self)
