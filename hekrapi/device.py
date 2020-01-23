# -*- coding: utf-8 -*-
"""Device class module for Hekr API"""
import asyncio
import logging
from json import dumps, loads
from typing import Optional, Any, TYPE_CHECKING, Dict, Set, Callable

from aiohttp import ClientSession, WSMsgType, client_exceptions

from .aioudp import RemoteEndpoint, open_remote_endpoint
from .command import Command
from .const import (
    DEFAULT_APPLICATION_ID,
    DeviceConnectionType,
    DeviceResponseState,
    ACTION_DEVICE_AUTH_RESPONSE, ACTION_CLOUD_AUTH_RESPONSE, ACTION_DEVICE_MESSAGE, ACTION_COMMAND_RESPONSE,
    ACTION_HEARTBEAT_RESPONSE, ACTION_HEARTBEAT_REQUEST, ACTION_DEVICE_AUTH_REQUEST, ACTION_COMMAND_REQUEST,
    ACTION_CLOUD_AUTH_REQUEST, DEFAULT_WEBSOCKET_HOST, DEFAULT_WEBSOCKET_PORT)
from .exceptions import *
from .helpers import sensitive_info_filter
from .types import MessageID, Action, ProcessedResponse, HekrCallback, DeviceResponse, DeviceInfo, \
    AnyCommand, CommandData, DeviceID, DevicesDict

if TYPE_CHECKING:
    from .protocol import Protocol
    from aiohttp.client import _WSRequestContextManager

_LOGGER = logging.getLogger(__name__)


class Listener:
    @staticmethod
    def _get_loop_run_executor(*args):
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, *args)

    def __init__(self, connector: '_BaseConnector',
                 callback_task_function: callable = None,
                 callback_exec_function: callable = None):
        self.connector = connector
        self._callbacks: Set[HekrCallback] = set()
        self._running: Optional[asyncio.Task] = None

        self._callback_exec_function = self._get_loop_run_executor if callback_exec_function is None \
            else callback_exec_function
        self._callback_task_function = asyncio.create_task if callback_task_function is None \
            else callback_task_function

    def __str__(self):
        return '<Hekr:Listener(' + ('running' if self.is_running else 'stopped') + ', ' + str(self.connector) + ')>'

    def add_callback(self, callback: HekrCallback) -> None:
        self._callbacks.add(callback)

    def del_callback(self, callback: HekrCallback) -> None:
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    @property
    def is_running(self):
        return self._running is not None and not self._running.cancelled()

    async def start_receiving(self):
        _LOGGER.debug('Start receiving on %s' % self)
        try:
            if not self.connector.is_connected:
                await self.connector.open_connection()

            while True:
                response_str = await self.connector.read_response()
                _LOGGER.debug('Listener %s received response %s' % (self, response_str))
                response_processed = self.connector.process_response(response_str)

                message_id, state, action, data, hekr_device = response_processed

                callback_task_function = self._callback_task_function
                callback_exec_function = self._callback_exec_function

                for callback in self._callbacks:
                    # process connector callbacks, if any
                    if asyncio.iscoroutinefunction(callback):
                        callback_task_function(callback(hekr_device, message_id, state, action, data))
                    else:
                        callback_exec_function(callback, hekr_device, message_id, state, action, data)

                if hekr_device is not None:
                    for callback in hekr_device.callbacks:
                        # process device callbacks, if any
                        if asyncio.iscoroutinefunction(callback):
                            callback_task_function(callback(hekr_device, message_id, state, action, data))
                        else:
                            callback_exec_function(callback, hekr_device, message_id, state, action, data)

        except asyncio.CancelledError:
            _LOGGER.debug('Closing listener')
        except Exception as e:
            _LOGGER.exception('Caught exception')
        finally:
            _LOGGER.debug('Finally on listener closing')

    def start(self, create_task_func: Callable = asyncio.create_task):
        _LOGGER.debug('Starting listener %s with factory: %s' % (self, create_task_func))
        self._running = create_task_func(self.start_receiving())

    def stop(self):
        if self.is_running:
            self._running.cancel()
        self._running = None


class _BaseConnector:
    """Base endpoint class for implementing other endpoints"""

    def __init__(self, device: Optional['Device'] = None, application_id: str = DEFAULT_APPLICATION_ID):
        self._last_message_id = 0
        self._message_devices: Dict[int, 'Device'] = dict()
        self._devices: Set['Device'] = set()
        self._listener = None
        self._application_id = application_id

        if device is not None:
            self.attach_device(device)

    @property
    def last_message_id(self) -> int:
        return self._last_message_id

    # base methods
    def attach_device(self, hekr_device: 'Device') -> None:
        """
        Attach device to connector.
        :param hekr_device: Device to attach
        """
        if hekr_device in self.devices:
            raise Exception('Trying to attach device %s when device with same device ID is attached' % hekr_device)

        self._devices.add(hekr_device)

    def detach_device(self, hekr_device: 'Device') -> None:
        if hekr_device not in self._devices:
            # @TODO: check for object similarity?
            raise Exception('Cannot detach an unattached device (%s)' % hekr_device)

        self._devices.remove(hekr_device)

    def is_attached(self, hekr_device: 'Device') -> bool:
        """Checkes whether device is attached."""
        return hekr_device in self._devices

    @property
    def devices(self) -> DevicesDict:
        """
        Access devices attached to this connector.
        :return: Dictionary of attached devices indexed by device ID.
        :rtype: Dict[str, 'Device']
        """
        return {hekr_device.device_id: hekr_device for hekr_device in self._devices}

    @property
    def listener(self) -> Optional[Listener]:
        """Return bound listener, if exists."""
        return self._listener

    def get_listener(self, listener_factory: Callable[['_BaseConnector'], Listener] = Listener) -> Listener:
        """
        Get existing listener, or create a new one.
        :return:
        """
        if self._listener is None:
            self._listener = listener_factory(self)
        return self._listener

    def _get_request_base(self, action: str, hekr_device: Optional['Device'] = None, message_id: int = None) -> (
            int, Dict[str, Any]):
        """
        Generate base of the action execution request.
        :param action: Action to execute
        :param hekr_device: (optional) Device to generate request for
        :param message_id: (optional) Specific message ID to use
        :return: Message ID, request payload
        """

        if message_id is None:
            message_id = self._last_message_id + 1

        request_dict = {
            "msgId": message_id,
            "action": action,
        }

        if action != ACTION_HEARTBEAT_REQUEST:
            if not hekr_device:
                raise HekrAPIException('Device not set for a "%s" action request' % action)

            if hekr_device.device_id not in self.devices:
                raise Exception('Device with ID %s is not attached' % hekr_device.device_id)

            request_dict["params"] = {
                "devTid": hekr_device.device_id,
                "ctrlKey": hekr_device.control_key,
            }
            if action.startswith("app"):
                request_dict["params"]["appTid"] = self._application_id

        return message_id, request_dict

    def generate_request(self, action: str, params: dict = None, hekr_device: Optional['Device'] = None,
                         message_id: int = None) -> (int, str):
        """
        Generate request string (JSON format).
        :param action: Action name (read README.md for discovered actions list)
        :param params: (optional) Parameters array for actions
        :param hekr_device: (optional) Device to generate request for
        :param message_id: (optional) Message id (default: last message id for set connection)
        :return: Message ID, request payload
        """
        message_id, request_dict = self._get_request_base(action, hekr_device, message_id)

        if isinstance(params, dict):
            request_dict['params'].update(params)

        self._message_devices[message_id] = hekr_device
        self._last_message_id = message_id

        return message_id, dumps(request_dict)

    def process_response(self, response_str: str) -> ProcessedResponse:
        """
        Handle incoming response packet (decode from existing string).
        :param response_str: Response string
        :return: Response state, response action, response contents, related device
        """
        state = DeviceResponseState.UNKNOWN
        data = loads(response_str)
        action = data.get('action')
        message_id = data.get('msgId')
        response_code = data.get('code', 200)  # @TODO: this is a compatibility-oriented default value

        hekr_device = None
        if message_id in self._message_devices:
            hekr_device = self._message_devices[message_id]
            del self._message_devices[message_id]

        elif 'params' in data and 'devTid' in data['params']:
            hekr_device = self.devices.get(data['params']['devTid'])

        if action == ACTION_HEARTBEAT_RESPONSE:
            """Handle heartbeat responses"""
            if response_code == 200:
                _LOGGER.debug('Heartbeat executed successfully on device %s', self)
                state = DeviceResponseState.SUCCESS
            else:
                _LOGGER.error('Heartbeat failed on device %s', self)
                state = DeviceResponseState.FAILURE

        elif action in (ACTION_COMMAND_RESPONSE, ACTION_DEVICE_MESSAGE):
            """Handle responses from command requests"""
            if not hekr_device:
                raise HekrAPIException('Device not attached to connector on response: %s' % data)

            if not hekr_device.protocol:
                raise DeviceProtocolNotSetException(device=self)

            if response_code == 200:
                data = hekr_device.protocol.decode(raw=data['params']['data']['raw'])
                command = data[1]
                _LOGGER.debug('Command executed successfully on device %s'
                              if action == ACTION_COMMAND_RESPONSE else
                              'Received command request for device %s', self)
                state = DeviceResponseState.SUCCESS
            else:
                _LOGGER.debug('Command failed on device %s, raw response: %s', self, data)
                state = DeviceResponseState.FAILURE

        return message_id, state, action, data, hekr_device

    async def send_heartbeat(self, hekr_device: Optional['Device'] = None) -> int:
        """
        Send heartbeat with connector.
        :param hekr_device: (optional) Device to send heartbeat to
        :return: Message ID
        """
        message_id, request_str = self.generate_request(ACTION_HEARTBEAT_REQUEST, hekr_device=hekr_device)
        await self.send_request(request_str)
        return message_id

    async def authenticate(self, action: str) -> None:
        _, request_str = self.generate_request(action)
        await self.send_request(request_str)

        response_str = await self.read_response()
        message_id, state, action, data, hekr_device = self.process_response(response_str)
        if state == DeviceResponseState.FAILURE:
            await self.close_connection()
            raise AuthenticationFailedException(reason='Endpoint %s rejected credentials (%s)' % (self, data))
        _LOGGER.debug('Authentication on %s successful' % self)

    # attributes and methods to be overridden wholly by inherent connectors
    connection_type: DeviceConnectionType = NotImplemented
    connection_priority: int = NotImplemented

    @property
    def is_connected(self) -> bool:
        """
        Get connection state of the connector.
        :return: Connection is open
        """
        raise NotImplementedError

    async def open_connection(self) -> None:
        """Open connection with connector."""
        raise NotImplementedError

    async def close_connection(self) -> None:
        """Close connection with connector."""
        raise NotImplementedError

    async def send_request(self, request_str: str) -> None:
        """
        Send request to device with connector.
        :param request_str: Request payload
        """
        raise NotImplementedError

    async def read_response(self) -> str:
        """
        Read response from connector
        :return: Response payload
        """
        raise NotImplementedError


class LocalConnector(_BaseConnector):
    """Endpoint via LAN"""
    connection_type = DeviceConnectionType.LOCAL
    connection_priority = 1000

    def __init__(self, host: str, port: int, hekr_device: Optional['Device'] = None,
                 application_id: str = DEFAULT_APPLICATION_ID) -> None:
        super().__init__(hekr_device, application_id)
        self._endpoint: Optional['RemoteEndpoint'] = None
        self._host = host
        self._port = port

    def __str__(self):
        return '<HekrApi:LocalConnector(' + self._host + ':' + str(self._port) + ')>'

    def attach_device(self, hekr_device: 'Device'):
        if self._devices:
            raise HekrAPIException('Cannot attach more than one device to a local socket')
        super().attach_device(hekr_device)

    def _get_request_base(self, action: str, hekr_device: Optional['Device'] = None, message_id: int = None) -> (
            int, Dict[str, Any]):
        hekr_device = next(iter(self._devices))
        return super()._get_request_base(action, hekr_device, message_id)

    async def open_connection(self) -> None:
        if self.is_connected:
            raise HekrAPIException('Local endpoint already established')
        if not self._devices:
            raise HekrAPIException('Device not set for local endpoint')

        _LOGGER.debug('Opening local endpoint on device %s' % self._devices)
        self._endpoint = await open_remote_endpoint(self._host, self._port)
        _LOGGER.debug('Sending authentication request to %s' % self._devices)

        await self.authenticate(ACTION_DEVICE_AUTH_REQUEST)

        _LOGGER.debug('Authentication request processed, local endpoint is open')

    async def close_connection(self) -> None:
        if self._endpoint is None:
            return

        if self._endpoint.closed:
            self._endpoint = None
            return

        _LOGGER.debug('Closing local endpoint on device %s' % self._devices)
        self._endpoint.close()
        if not self._endpoint.closed:
            raise HekrAPIException('Could not close existing endpoint')

        self._endpoint = None

    async def send_request(self, request_str: str) -> None:
        _LOGGER.debug('Sending request via %s with content: %s' % (self, request_str))
        self._endpoint.send(str.encode(request_str))

    async def read_response(self) -> str:
        _LOGGER.debug('Starting receiving on %s' % self)
        response = await self._endpoint.receive()
        _LOGGER.debug('Received response on %s with content: %s' % (self, response))
        return response.decode('utf-8').strip()

    @property
    def is_connected(self) -> bool:
        return self._endpoint is not None

    def process_response(self, response_str: str) -> ProcessedResponse:
        message_id, state, action, data, device = super().process_response(response_str)
        if state == DeviceResponseState.UNKNOWN:
            response_code = data.get('code')

            if action == ACTION_DEVICE_AUTH_RESPONSE:
                """Handle local authentication responses"""
                if response_code == 200:
                    _LOGGER.debug('Authentication executed successfully on device %s', self)
                    state = DeviceResponseState.SUCCESS
                else:
                    _LOGGER.error('Authentication failed on device %s', self)
                    state = DeviceResponseState.FAILURE

        return message_id, state, action, data, device


class CloudConnector(_BaseConnector):
    """Endpoint via cloud"""
    connection_type = DeviceConnectionType.CLOUD
    connection_priority = 2000

    def __init__(self, token: str, device: Optional['Device'] = None, application_id: str = DEFAULT_APPLICATION_ID,
                 connect_host: str = DEFAULT_WEBSOCKET_HOST, connect_port: int = DEFAULT_WEBSOCKET_PORT) -> None:
        super().__init__(device, application_id)
        self.__token = token
        self._session: Optional[ClientSession] = None
        self._endpoint: Optional['_WSRequestContextManager'] = None
        self._connect_host = connect_host
        self._connect_port = connect_port

    def __str__(self) -> str:
        return '<Hekr:CloudConnector(' + self._connect_host + ':' + str(self._connect_port) + ')>'

    @property
    def is_connected(self) -> bool:
        return self._endpoint is not None and self._session is not None

    async def open_connection(self) -> None:
        _LOGGER.debug('Opening cloud endpoint to device %s' % self._connect_host)
        session = ClientSession()
        try:
            from random import getrandbits
            from base64 import b64encode
            raw_key = bytes(getrandbits(8) for _ in range(16))
            websocket_key = b64encode(raw_key).decode()

            self._endpoint = await session.ws_connect(
                'https://' + self._connect_host + ':' + str(self._connect_port) + '/',
                headers={
                    'Sec-WebSocket-Key': websocket_key,
                    'Sec-WebSocket-Version': '13',
                    'Connection': 'upgrade',
                    'Upgrade': 'websocket'
                })
            self._session = session
            _LOGGER.debug('Cloud endpoint opened on device %s', self)

            await self.authenticate(ACTION_CLOUD_AUTH_REQUEST)

            _LOGGER.debug('Authentication request processed, cloud endpoint is open')

        except client_exceptions.ClientConnectionError:
            _LOGGER.exception('Client connection could not be established')
            await session.close()

    async def close_connection(self) -> None:
        if not self.is_connected:
            return None

        try:
            await self._endpoint.close()
            await self._session.close()

        except BaseException:
            _LOGGER.exception('Exception occurred while trying to close %s' % self)
            raise

        finally:
            self._session = None
            self._endpoint = None

    def _get_request_base(self, action: str, hekr_device: Optional['Device'] = None, message_id: int = None) -> (
            int, Dict[str, Any]):
        if action == ACTION_CLOUD_AUTH_REQUEST:
            if message_id is None:
                message_id = self._last_message_id

            request_dict = {
                "msgId": message_id,
                "action": action,
                "params": {
                    "appTid": self._application_id,
                    "token": self.__token
                }
            }

            self._last_message_id = message_id

        else:
            message_id, request_dict = super()._get_request_base(action, hekr_device, message_id)

            if action == ACTION_CLOUD_AUTH_REQUEST:
                if 'params' in request_dict and 'token' not in request_dict['params']:
                    request_dict['params']['token'] = self.__token

        return message_id, request_dict

    async def send_request(self, request_str: str) -> None:
        await self._endpoint.send_str(request_str)

    async def read_response(self) -> str:
        message = await self._endpoint.receive()
        if message.type == WSMsgType.TEXT:
            response_str = message.data
        elif message.type == WSMsgType.BINARY:
            response_str = message.data.decode('utf-8')
        else:
            raise Exception('Unknown response from WebSockets: %s', message)
        return response_str

    def process_response(self, response_str: str) -> ProcessedResponse:
        message_id, state, action, data, device = super().process_response(response_str)
        if state == DeviceResponseState.UNKNOWN:
            response_code = data.get('code')

            if action == ACTION_CLOUD_AUTH_RESPONSE:
                """Handle cloud authentication responses"""
                if response_code == 200:
                    _LOGGER.debug('Cloud authentication executed successfully on device %s', self)
                    state = DeviceResponseState.SUCCESS
                else:
                    _LOGGER.error('Cloud authentication failed on device %s', self)
                    state = DeviceResponseState.FAILURE

        return message_id, state, action, data, device


class Device:
    """Device class for Hekr API"""

    def __init__(self, device_id: DeviceID, control_key: str, protocol: Optional['Protocol'] = None,
                 device_info: Dict[str, Any] = None):
        self.protocol = protocol
        self.device_id = device_id
        self.control_key = control_key
        self._device_info = device_info
        self.heartbeat_interval = 30

        self._connector: Optional[_BaseConnector] = None
        self._callbacks: Set[HekrCallback] = set()

        self.__last_frame_number = 0

    def __str__(self) -> str:
        """
        Generates a string representation of the device
        :return: String representation (human-readable)
        """

        return '<Hekr:Device(' + self.device_id + ')>'

    def __repr__(self) -> str:
        """
        Generates debug string representation of the device
        :return: String representation (python-like)
        """
        return '<{}({}, {})>'.format(
            self.__class__.__name__,
            self.device_id,
            self._connector if self._connector else 'no connector'
        )

    def __eq__(self, other: 'Device') -> bool:
        """
        Compare device ID to other device's ID.
        :param other: Other device
        :return: Comparison result
        """
        if not isinstance(other, Device):
            raise Exception('Comparison with type "%s" is not implemented' % type(other))
        return self.device_id == other.device_id

    def __hash__(self) -> int:
        """
        Generate hash of the device (primarily for sets).
        :return: Hash of the device ID
        """
        return hash(self.device_id)

    @property
    def callbacks(self):
        return self._callbacks

    # callback management
    def add_callback(self, callback: HekrCallback) -> None:
        self._callbacks.add(callback)

    def del_callback(self, callback: HekrCallback) -> None:
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    # connection management
    @property
    def connector(self) -> Optional[_BaseConnector]:
        return self._connector

    @connector.setter
    def connector(self, connector: Optional[_BaseConnector]) -> None:
        old_connector = self._connector
        if old_connector is not None and old_connector.is_attached(self):
            old_connector.detach_device(self)
        self._connector = connector
        if connector is not None:
            connector.attach_device(self)

    async def open_connection(self) -> _BaseConnector:
        """Open connection with available connector."""
        connector = self.connector
        if connector is None:
            raise HekrAPIException('No connector attached to device')

        if not connector.is_connected:
            await connector.open_connection()

        return connector

    async def close_connection(self) -> None:
        """Close open connector for the device."""
        connector = self.connector
        if connector is None:
            raise HekrAPIException('No connector attached to device')

        if connector.is_connected:
            await connector.close_connection()

    # request management
    async def make_request(self, action: Action, params: dict = None,
                           message_id: Optional[MessageID] = None) -> MessageID:
        """
        Make request to device.

        :param action: Action name.
        :param params: Request parameters.
        :param message_id: Message ID.
        :type action: str
        :type params: dict
        :type message_id: int
        :return: Message ID
        """
        connector = await self.open_connection()

        (message_id, request_str) = connector.generate_request(action=action, params=params, hekr_device=self,
                                                               message_id=message_id)

        _LOGGER.debug('Composed request for device %s, content: %s', self, sensitive_info_filter(request_str))

        await connector.send_request(request_str)
        return message_id

    async def get_response(self, message_id: Optional[MessageID] = None) -> DeviceResponse:
        """
        Read response from device and process.
        :param message_id:
        :return:
        """
        connector = await self.open_connection()

        response_str = await connector.read_response()
        resp_message_id, state, action, data, device = connector.process_response(response_str)

        if message_id is not None and message_id != resp_message_id:
            raise HekrAPIException('Received message for a different request (expected mID: %d, got: %d)'
                                   % (message_id, resp_message_id))

        _LOGGER.debug('Received response for device %s: %s', self, sensitive_info_filter(response_str))

        return resp_message_id, state, action, data

    # shorthand request commands
    async def heartbeat(self) -> int:
        """Send heartbeat message

        Keyword Arguments:
            connection_type {DeviceConnectionType} -- Connection type to use (default: {None})

        Raises:
            HeartbeatFailedException: Heartbeat message sending failed
        """
        return await self.make_request(ACTION_HEARTBEAT_REQUEST)

    async def command(self, command: AnyCommand, data: CommandData = None, frame_number: int = None) -> MessageID:
        """
        Execute device command.
        :param command: Command ID/name/object
        :param data: (optional) Data values for datagram
        :param frame_number: (optional) Frame number
        :return: Message ID
        """
        if not isinstance(command, Command):
            if not self.protocol:
                raise DeviceProtocolNotSetException(self)
            command = self.protocol.get_command(command)

        if frame_number is None:
            frame_number = self.__last_frame_number + 1

        self.__last_frame_number = frame_number

        raw = self.protocol.encode(
            data=data,
            command=command,
            frame_number=frame_number
        )

        return await self.make_request(ACTION_COMMAND_REQUEST, {"data": {"raw": raw}})

    # device info-related accessors
    @property
    def device_info(self) -> Optional[DeviceInfo]:
        """
        Accessor to get device info and raise exception if it is not set.
        :return: Device info response from cloud, if set
        """
        return self._device_info

    @device_info.setter
    def device_info(self, new_info: DeviceInfo) -> None:
        """
        Update device info with provided values.
        :param new_info: Device info response from cloud
        """
        new_info = {**new_info}
        if self._device_info is None:
            self._device_info = new_info
        else:
            self._device_info.update(new_info)

        if 'ctrlKey' in new_info:
            self.control_key = new_info['ctrlKey']

    @property
    def _device_info_for_property(self) -> DeviceInfo:
        """
        Shorthand accessor to get device info and raise exception if it is not set.
        :return: Device info response from cloud
        :raises HekrAPIException: No device info is added before property access
        """
        device_info = self._device_info
        if device_info is None:
            raise HekrAPIException('Device info has not been updated because device appears to be created standalone.')
        return self.device_info

    @property
    def product_name(self) -> str:
        return self._device_info_for_property['productName']['en_US']

    @property
    def category_name(self) -> str:
        return self._device_info_for_property['categoryName']['en_US']

    @property
    def sdk_version(self) -> str:
        return self._device_info_for_property['sdkVer']

    @property
    def firmware_version(self) -> str:
        return self._device_info_for_property['binVersion']

    @property
    def url_logo(self) -> str:
        return self._device_info_for_property['logo']

    @property
    def mac_address(self) -> str:
        return self._device_info_for_property['mac']

    @property
    def lan_address(self) -> str:
        return self._device_info_for_property['lanIp']

    @property
    def wan_address(self) -> str:
        return self._device_info_for_property['gis']['ip']['ip']

    @property
    def is_online(self) -> bool:
        return self._device_info_for_property['online']

    @property
    def rssi(self) -> int:
        return self._device_info_for_property['rssi']

    @property
    def bind_key(self) -> str:
        return self._device_info_for_property['bindKey']

    @property
    def device_name(self):
        return self._device_info_for_property['deviceName']
