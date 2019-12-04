# -*- coding: utf-8 -*-
"""Device class module for Hekr API"""
import logging

from aiohttp import ClientSession, WSMsgType, client_exceptions
from typing import Tuple, Union, Optional, AnyStr, Any, TYPE_CHECKING, List
from json import dumps, loads

from .helpers import sensitive_info_filter, generate_ws_key
from .aioudp import open_remote_endpoint
from .command import Command
from .exceptions import *
from .const import (
    DEFAULT_APPLICATION_ID,
    DEFAULT_DEVICE_PORT,
    DEFAULT_REQUEST_RETRIES,
    DeviceConnectionType,
    DeviceResponseState
)

if TYPE_CHECKING:
    from .protocol import Protocol

_LOGGER = logging.getLogger(__name__)


class Device:
    """Device class for Hekr API"""

    def __init__(self,
                 device_id: str,
                 control_key: str,
                 host: Optional[str] = None,
                 port: int = DEFAULT_DEVICE_PORT,
                 protocol: Optional['Protocol'] = None,
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
        self.__cloud_session = None
        self.__cloud_authenticated = False
        self.__cloud_token = None
        self.__cloud_domain = None

        self.__local_endpoint = None
        self.__local_authenticated = False

    def __str__(self) -> str:
        """
        Generates a string representation of the device
        :return: String representation (human-readable)
        """
        available_connection_types = self.available_connection_types

        if DeviceConnectionType.LOCAL in available_connection_types:
            return '{}@{}:{}'.format(self.device_id, *self.local_address)

        if DeviceConnectionType.CLOUD in available_connection_types:
            return '{}@hekr-cloud'.format(self.device_id)

        return '{}'.format(self.device_id)

    def __repr__(self) -> str:
        """
        Generates debug string representation of the device
        :return: String representation (python-like)
        """
        available_connection_types = self.available_connection_types
        return '<{}({}, {})>'.format(
            self.__class__.__name__,
            self.device_id,
            ':'.join(map(str, self.local_address))
            if DeviceConnectionType.LOCAL in available_connection_types
            else 'hekr-cloud'
            if DeviceConnectionType.CLOUD in available_connection_types
            else 'not connected'
        )

    def generate_request(self,
                         connection_type: DeviceConnectionType,
                         action: str,
                         params: dict = None,
                         message_id: int = None
                         ) -> Tuple[int, str]:
        """
        Generate request string (JSON format).

        :param connection_type: Connection type request will be used in.
        :param action: Action name (read README.md for discovered actions list).
        :param params: Parameters array for actions (not required for some actions).
        :param message_id: Message id (default: last message id for set connection).
        :return: Message ID, request payload
        :rtype: (int, bytes)
        """
        connection_type = connection_type or self.default_connection_type
        if connection_type is None:
            raise HekrValueError(variable='connection_type',
                                 expected='valid connection type',
                                 got=None)

        if message_id is None:
            message_id = self.__last_message_id + 1

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

        return message_id, dumps(request_dict)

    @property
    def available_connection_types(self) -> List[DeviceConnectionType]:
        """
        Retrieve all available connection types for current device
        :return: List of connection types
        :rtype: list[DeviceConnectionType]
        """
        # @TODO: check for more stuff to determine connection type
        connection_types = []
        if self.__local_endpoint is not None:
            connection_types.append(DeviceConnectionType.LOCAL)
        if self.__cloud_endpoint is not None:
            connection_types.append(DeviceConnectionType.CLOUD)
        return connection_types

    @property
    def default_connection_type(self) -> Optional[DeviceConnectionType]:
        """
        Default connection type for the device
        :return: Available device connection type
        """
        if self.__local_endpoint is not None:
            return DeviceConnectionType.LOCAL
        if self.__cloud_endpoint is not None:
            return DeviceConnectionType.CLOUD

    def set_control_key(self, control_key: str) -> None:
        """
        Sets device's control key
        :param control_key: Control key
        :type control_key: str
        """
        self.__control_key = control_key

    def set_cloud_settings(self, cloud_token: str, cloud_domain: str) -> None:
        """Sets settings for cloud authentication

        Arguments:
            cloud_token {str} -- Cloud authentication token
            cloud_domain {str} -- Cloud authentication domain
        """
        if self.__cloud_domain != cloud_domain or self.__cloud_token != cloud_token:
            self.__cloud_authenticated = False

        self.__cloud_token = cloud_token
        self.__cloud_domain = cloud_domain

    async def open_socket_local(self) -> bool:
        """Opens local socket to device

        Returns:
            bool -- State of socket opening
        """
        _LOGGER.debug('Opening local endpoint on device %s', self)
        self.__local_endpoint = await open_remote_endpoint(*self.local_address)
        return True

    async def open_socket_cloud(self) -> bool:
        """
        Opens cloud socket to device
        :return: Cloud endpoint opening status
        :rtype: bool
        """
        _LOGGER.debug('Opening cloud endpoint on device %s', self)
        self.__cloud_session = ClientSession()
        try:
            self.__cloud_endpoint = await self.__cloud_session.ws_connect(
                'https://{}:186/'.format(self.__cloud_domain),
                headers={
                    'Sec-WebSocket-Key': generate_ws_key(),
                    'Sec-WebSocket-Version': '13',
                    'Connection': 'upgrade',
                    'Upgrade': 'websocket'
                })
            _LOGGER.debug('Cloud endpoint opened on device %s', self)
            return True
        except client_exceptions.ClientConnectionError:
            _LOGGER.exception('Client connection could not be established')
            await self.__cloud_session.close()
            return False

    async def close_socket_cloud(self) -> bool:
        """
        Closes cloud endpoint
        :return: Cloud endpoint closing status
        :rtype: bool
        """
        if self.__cloud_endpoint:
            await self.__cloud_endpoint.close()
        if self.__cloud_session:
            await self.__cloud_session.close()
        return True

    def process_response(self, response: AnyStr, message_id: int) -> Tuple[DeviceResponseState, str, Any]:
        """
        Handle incoming response packet (decode from existing string).

        :param response: Raw response contents
        :param message_id: Message identifier (expect response)
        :return: Response state, response action, response contents
        """
        if isinstance(response, bytes):
            response_str = response.decode('utf-8')
        else:
            response_str = str(response)
        response_str = response_str.strip()

        _LOGGER.debug('Received response for device %s: %s', self, sensitive_info_filter(response_str))

        response_dict = loads(response_str)

        # @TODO: compare message ids to verify correct request sequence
        # response_message_id = response_dict.get('msgId')

        data = response_dict
        action = response_dict.get('action')
        if action == 'appDevAuthResp':
            """Handle local authentication responses"""
            if response_dict.get('code') == 200:
                _LOGGER.debug('Authentication executed successfully on device %s', self)
                self.__local_authenticated = True
                state = DeviceResponseState.SUCCESS
            else:
                _LOGGER.error('Authentication failed on device %s', self)
                self.__local_authenticated = False
                state = DeviceResponseState.FAILURE

        elif action == 'appLoginResp':
            """Handle cloud authentication responses"""
            if response_dict.get('code') == 200:
                _LOGGER.debug('Authentication executed successfully on device %s', self)
                self.__cloud_authenticated = True
                state = DeviceResponseState.SUCCESS
            else:
                _LOGGER.error('Authentication failed on device %s', self)
                self.__cloud_authenticated = False
                state = DeviceResponseState.FAILURE

        elif action == 'heartbeatResp':
            """Handle heartbeat responses"""
            if response_dict.get('code') == 200:
                _LOGGER.debug('Heartbeat executed successfully on device %s', self)
                state = DeviceResponseState.SUCCESS
            else:
                _LOGGER.error('Heartbeat failed on device %s', self)
                state = DeviceResponseState.FAILURE

        elif action == 'appSendResp':
            """Handle responses from command requests"""
            if not self.protocol:
                raise DeviceProtocolNotSetException(device=self)

            if response_dict.get('code') == 200:
                cur_command, _, _ = self.protocol.decode(raw=response_dict['params']['data']['raw'])
                if cur_command.response_command_id:
                    next_command = self.protocol.get_command(cur_command.response_command_id)
                    _LOGGER.debug('Command %s should wait for next response from command %s on device %s', cur_command,
                                  next_command, self)
                    state = DeviceResponseState.WAIT_NEXT
                else:
                    _LOGGER.debug('Command %s executed successfully on device %s', cur_command, self)
                    state = DeviceResponseState.SUCCESS
            else:
                _LOGGER.debug('Command failed on device %s, raw response: %s', self, response)
                state = DeviceResponseState.FAILURE

        elif action == 'devSend':
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

        return state, action, data

    async def make_request(self, action: str,
                           params: dict = None,
                           message_id: int = None,
                           connection_type: DeviceConnectionType = None)\
            -> Tuple[DeviceResponseState, Optional[str], Optional[dict]]:
        """
        Make request to device.

        :param action: Action name.
        :param params: Request parameters.
        :param message_id: Message ID.
        :param connection_type: Connection type to use.
        :type action: str
        :type params: dict
        :type message_id: int
        :type connection_type: DeviceConnectionType
        :return: Response state, response action, response data
        """
        connection_type = connection_type or self.default_connection_type
        if connection_type is None or connection_type not in self.available_connection_types:
            raise DeviceConnectionMissingException(device=self)

        (message_id, request) = self.generate_request(
            connection_type=connection_type,
            action=action,
            params=params,
            message_id=message_id
        )

        _LOGGER.debug('Composed request for device %s, content: %s', self, sensitive_info_filter(request))

        if connection_type == DeviceConnectionType.LOCAL:
            if not self.__local_endpoint:
                await self.open_socket_local()
            self.__local_endpoint.send(str.encode(request))
        elif connection_type == DeviceConnectionType.CLOUD:
            if not self.__cloud_endpoint:
                await self.open_socket_cloud()
            await self.__cloud_endpoint.send_str(request)
        else:
            raise HekrValueError(variable='connection_type',
                                 expected=self.available_connection_types,
                                 got=connection_type)

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
                    return DeviceResponseState.FAILURE, None, message
            else:
                raise HekrValueError(variable='connection_type',
                                     expected=self.available_connection_types,
                                     got=connection_type)

            (state, action, data) = self.process_response(data, message_id)

            if state != DeviceResponseState.WAIT_NEXT:
                return state, action, data

            retries += 1

        _LOGGER.debug('Received too many %s responses, marking request result as invalid on device %s',
                      DeviceResponseState.WAIT_NEXT.name, self)
        return DeviceResponseState.FAILURE, None, None

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
            params=None,
            connection_type=connection_type)

    async def authenticate(self, connection_type: DeviceConnectionType = None):
        """Authenticate with the device

        Keyword Arguments:
            connection_type {DeviceConnectionType} -- Connection type to use (default: {None})

        Raises:
            LocalAuthenticationFailedException: Local authentication failed
            AuthenticationFailedException: Authentication failed
        """
        connection_type = connection_type or self.default_connection_type
        if connection_type is None or \
                connection_type not in self.available_connection_types:
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
                      frame_number: int = None,
                      return_decoded: bool = True,
                      connection_type: DeviceConnectionType = None):
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
