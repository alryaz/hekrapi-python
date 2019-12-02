# -*- coding: utf-8 -*-
"""Device class module for Hekr API"""
import asyncio
import logging
import re

from aiohttp import ClientSession, WSMsgType, client_exceptions
from typing import Union
from enum import IntEnum, Enum
from json import (dumps, loads)
from random import getrandbits
from base64 import b64encode

from .aioudp import open_datagram_endpoint, open_remote_endpoint
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
    DEFAULT_DEVICE_PORT,
    DEFAULT_REQUEST_RETRIES,
    DEFAULT_RETRY_DELAY
)

_LOGGER = logging.getLogger(__name__)

SENSITIVE_INFO_REGEX = re.compile(r'("(ctrlKey|token)"\s*:\s*")[^"]+(")')
SENSITIVE_INFO_FILTER = lambda content: SENSITIVE_INFO_REGEX.sub(r'\1<redacted>\3', content)

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

class DeviceResponseState(Enum):
    SUCCESS = 0
    FAILURE = 1
    WAIT_NEXT = 2

class DeviceConnectionType(Enum):
    """Connection types for devices"""
    NONE = 0
    LOCAL = 1
    CLOUD = 2

class Device:
    """Device class for Hekr API"""

    def __init__(self,
                 device_id: str,
                 control_key: str,
                 host: Union[str, type(None)]=None,
                 port: int = DEFAULT_DEVICE_PORT,
                 protocol: Union['Protocol', type(None)]=None,
                 application_id: str = DEFAULT_APPLICATION_ID
                 ):
        self.device_id = device_id
        self.local_address = (host, port)
        self.protocol = protocol
        self.application_id = application_id

        self.__control_key = control_key

        self.__last_frame_number = 0
        self.__last_message_id = 0

        self.__cloud_endpoint = None
        self.__cloud_authenticated = False
        self.__cloud_token = None
        self.__cloud_domain = None

        self.__local_endpoint = None
        self.__local_authenticated = False

    def __str__(self):
        if self.available_connection_type == DeviceConnectionType.LOCAL:
            return '{}@{}:{}'.format(self.device_id, *self.local_address)
        elif self.available_connection_type == DeviceConnectionType.CLOUD:
            return '{}@hekr-cloud'.format(self.device_id)
        elif self.available_connection_type == DeviceConnectionType.NONE:
            return '{}'.format(self.device_id)

    def __repr__(self):
        return '<{}({}, {})>'.format(
            self.__class__.__name__,
            self.device_id,
            ':'.join(map(str,self.local_address))
                if self.available_connection_type == DeviceConnectionType.LOCAL
                else 'hekr-cloud'
                if self.available_connection_type == DeviceConnectionType.CLOUD
                else DeviceConnectionType.NONE.name
        )

    def generate_request(self, action:str, params:dict=None, message_id:int=None, connection_type:DeviceConnectionType=None):
        """Generate request string (JSON format)

        Arguments:
            action {str} -- Action name (read README.md for discovered actions list)

        Keyword Arguments:
            params {dict} -- parameters array for actions (not required for some actions) (default: {None})
            message_id {int} -- message id (default: last message id for set connection)
            connection_type {DeviceConnectionType} -- set connection (default: {self.available_connection})

        Raises:
            NotImplementedError: Cloud request generation not yet implemented
            DeviceConnectionMissingException: Device connection missing

        Returns:
            bytes -- Bytes-encoded JSON request
        """
        connection_type = connection_type or self.available_connection_type

        if message_id is None:
            self.__last_message_id += 1
            message_id = self.__last_message_id

        request_dict = {
            "msgId": message_id,
            "action": action,
        }

        if action != 'heartbeat':
            request_dict["params"] = {
                "ctrlKey": self.__control_key,
                "devTid": self.device_id
            }

            if connection_type == DeviceConnectionType.LOCAL:
                # No additional data required for local connections
                pass
            elif connection_type == DeviceConnectionType.CLOUD:
                request_dict["params"]["appTid"] = self.application_id

        if isinstance(params, dict):
            request_dict['params'].update(params)

        return (message_id, str.encode(dumps(request_dict)))

    @property
    def available_connection_type(self) -> DeviceConnectionType:
        """Retrieve best available connection type for communication

        Returns:
            DeviceConnectionType -- Available connection type
        """
        # @TODO: check for more stuff to determine connection type
        if self.__local_endpoint is not None:
            return DeviceConnectionType.LOCAL
        if self.__cloud_endpoint is not None:
            return DeviceConnectionType.CLOUD

        return DeviceConnectionType.NONE

    def set_control_key(self, control_key: str):
        """Sets device control key

        Arguments:
            control_key {str} -- Control key
        """
        self.__control_key = control_key

    def set_cloud_settings(self, cloud_token: str, cloud_domain: str):
        if self.__cloud_domain != cloud_domain or self.__cloud_token != cloud_token:
            self.__cloud_authenticated = False

        self.__cloud_token = cloud_token
        self.__cloud_domain = cloud_domain

    async def open_socket_local(self):
        """Opens local socket to device"""
        _LOGGER.debug('Opening local endpoint on device %s', self)
        self.__local_endpoint = await open_remote_endpoint(*self.local_address)
        return True

    def _generate_websocket_key(self):
        raw_key = bytes(getrandbits(8) for _ in range(16))
        return b64encode(raw_key).decode()

    async def open_socket_cloud(self):
        """Opens cloud socket to device"""
        _LOGGER.debug('Opening cloud endpoint on device %s', self)
        try:
            session = ClientSession()
            self.__cloud_endpoint = await session.ws_connect(
                'https://{}:186/'.format(self.__cloud_domain),
                headers={
                    'Sec-WebSocket-Key': self._generate_websocket_key,
                    'Sec-WebSocket-Version': '13',
                    'Connection': 'upgrade',
                    'Upgrade': 'websocket'
                })
            _LOGGER.debug('Cloud endpoint opened on device %s', self)
            return True
        except client_exceptions.ClientConnectionError:
            _LOGGER.exception('Client connection could not be established')
            await session.close()
            return False

    def _handle_incoming_response(self, response:dict, message_id:int):
        if isinstance(response, bytes):
            data = response.decode('utf-8')
        else:
            data = response
        data = data.strip()

        _LOGGER.debug('Received response for device %s: %s', self, SENSITIVE_INFO_FILTER(data))

        response_dict = loads(data)

        # @TODO: compare message ids to verify correct request sequence
        #response_message_id = response_dict.get('msgId')

        if response_dict.get('action') == 'appDevAuthResp':
            """Handle authentication responses"""
            if response_dict.get('code') == 200:
                _LOGGER.debug('Authentication executed succesfully on device %s', self)
                self.__local_authenticated = True
                state = DeviceResponseState.SUCCESS
            else:
                _LOGGER.error('Authentication failed on device %s', self)
                self.__local_authenticated = False
                state = DeviceResponseState.FAILURE

        elif response_dict.get('action') == 'appLoginResp':
            if response_dict.get('code') == 200:
                _LOGGER.debug('Authentication executed succesfully on device %s', self)
                self.__cloud_authenticated = True
                state = DeviceResponseState.SUCCESS
            else:
                _LOGGER.error('Authentication failed on device %s', self)
                self.__cloud_authenticated = False
                state = DeviceResponseState.FAILURE

        elif response_dict.get('action') == 'heartbeatResp':
            """Handle heartbeat responses"""
            if response_dict.get('code') == 200:
                _LOGGER.debug('Heartbeat executed succesfully on device %s', self)
                state = DeviceResponseState.SUCCESS
            else:
                _LOGGER.error('Heartbeat failed on device %s', self)
                state = DeviceResponseState.FAILURE

        elif response_dict.get('action') == 'appSendResp':
            """Handle responses from command requests"""
            if response_dict.get('code') == 200:
                (command, _, _) = self.protocol.decode(raw=response_dict['params']['data']['raw'])
                if command.response_command_id:
                    next_command = self.protocol.get_command(command.response_command_id)
                    _LOGGER.debug('Command %s should wait for next response from command %s on device %s', command, next_command, self)
                    state = DeviceResponseState.WAIT_NEXT
                else:
                    _LOGGER.debug('Command %s executed succesfully on device %s', command, self)
                    state = DeviceResponseState.SUCCESS
            else:
                _LOGGER.debug('Command %s failed on device %s', command, self)
                state = DeviceResponseState.FAILURE

        elif response_dict.get('action') == 'devSend':
            """Handle device status updates"""
            if not self.protocol:
                raise DeviceProtocolNotSetException(device=self)

            decoded = self.protocol.decode(raw=response_dict['params']['data']['raw'])

            _LOGGER.debug('Received command response for device %s: %s', self, decoded)

            state = DeviceResponseState.SUCCESS
            data = decoded
        else:
            _LOGGER.debug('Unknown response received on device %s: %s', self, response_dict)
            state = DeviceResponseState.FAILURE

        return (state, data)

    async def make_request(self, action: str, params: dict = None,
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
            retries {int} -- Amount of attempts the request should be made after it fails

        Returns:
            dict -- Request response
        """
        connection_type = connection_type or self.available_connection_type
        if connection_type == DeviceConnectionType.NONE:
            raise DeviceConnectionMissingException(device=self)

        (message_id, request) = self.generate_request(
            action=action,
            params=params,
            connection_type=connection_type
        )

        # @TODO: maybe move encoding to `generate_request`?
        request_str = request.decode('utf-8')

        _LOGGER.debug('Composed request for device %s, content: %s', self, SENSITIVE_INFO_FILTER(request_str))

        if connection_type == DeviceConnectionType.LOCAL:
            if not self.__local_endpoint:
                await self.open_socket_local()
            self.__local_endpoint.send(request)
        elif connection_type == DeviceConnectionType.CLOUD:
            if not self.__cloud_endpoint:
                await self.open_socket_cloud()
            await self.__cloud_endpoint.send_str(request_str)

        retries = 0
        while retries < DEFAULT_REQUEST_RETRIES:
            if connection_type == DeviceConnectionType.LOCAL:
                data = await self.__local_endpoint.receive()
            elif connection_type == DeviceConnectionType.CLOUD:
                message = await self.__cloud_endpoint.receive()

                if message.type == WSMsgType.TEXT:
                    data = message.data
                elif message.type == WSMsgType.BINARY:
                    data = message.data.decode('utf-8')
                else:
                    return (DeviceResponseState.FAILURE, data)

            (state, data) = self._handle_incoming_response(data, message_id)

            if state == DeviceResponseState.WAIT_NEXT:
                retries += 1
                continue

            return (state, data)

        _LOGGER.debug('Received too many %s responses, marking request result as invalid on device %s', DeviceResponseState.WAIT_NEXT.name, self)
        return (DeviceResponseState.FAILURE, data)

    async def heartbeat(self,
                        connection_type: DeviceConnectionType = None):
        """Send heartbeat message

        Keyword Arguments:
            connection_type {DeviceConnectionType} -- Connection type to use (default: {None})

        Raises:
            HeartbeatFailedException: Heartbeat message sending failed
        """
        _LOGGER.debug('Requesting heartbeat on device %s', self)
        return await self.make_request(
            action='heartbeat',
            params=False,
            connection_type=connection_type)

    async def authenticate(self, connection_type: DeviceConnectionType = None):
        """Authenticate with the device

        Keyword Arguments:
            connection_type {DeviceConnectionType} -- Connection type to use (default: {None})

        Raises:
            LocalAuthenticationFailedException: Local authentication failed
            AuthenticationFailedException: Authentication failed
        """
        connection_type = connection_type or self.available_connection_type
        if connection_type == DeviceConnectionType.NONE:
            raise DeviceConnectionMissingException(device=self)

        if connection_type == DeviceConnectionType.LOCAL:
            return await self.make_request(
                    action='appDevAuth',
                    connection_type=connection_type)

        if connection_type == DeviceConnectionType.CLOUD:
            params = {"token": self.__cloud_token}
            return await self.make_request(
                    action='appLogin',
                    connection_type=connection_type,
                    params=params)

    async def command(self,
                command: Union[int, str, Command],
                data: dict = None,
                frame_number:int=None,
                return_decoded:bool=True,
                connection_type:DeviceConnectionType=None):
        """Execute device command and return response

        Arguments:
            command {Union[int, str, Command]} -- Command ID/name/object to use

        Keyword Arguments:
            data {dict} -- Data values for datagram (default: {None})
            return_decoded {bool} -- Extract and decode datagram from response (default: {True})
            connection_type {DeviceConnectionType} -- Connection type to use (default: {None})

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

        if frame_number is None:
            self.__last_frame_number += 1
            frame_number = self.__last_frame_number

        connection_type = connection_type or self.available_connection_type

        raw = self.protocol.encode(
            data=data,
            command=command,
            frame_number=frame_number
        )

        request_dict = {"appTid": self.application_id, "data": {"raw": raw}}

        return await self.make_request(
            action='appSend',
            params=request_dict,
            connection_type=connection_type
        )