# -*- coding: utf-8 -*-
"""Device class module for Hekr API"""
import asyncio
import logging
from abc import ABC
from functools import partial
from json import dumps, loads, JSONDecodeError
from time import time
from types import MappingProxyType
from typing import Optional, Any, TYPE_CHECKING, Dict, Set, Callable, List, Tuple, TypeVar, Union, NamedTuple, Iterable, \
    Mapping
from weakref import WeakValueDictionary, ref

from aiohttp import ClientSession, client_exceptions, WSMsgType, ClientWebSocketResponse

from .const import (
    DEFAULT_APPLICATION_ID,
    DeviceResponseState,
    ACTION_DEVICE_MESSAGE, ACTION_COMMAND_RESPONSE,
    ACTION_HEARTBEAT_RESPONSE, ACTION_HEARTBEAT_REQUEST, ACTION_DEVICE_AUTH_REQUEST, ACTION_COMMAND_REQUEST,
    DEFAULT_TIMEOUT, DEFAULT_WEBSOCKET_HOST, DEFAULT_WEBSOCKET_PORT, ACTION_DEVICE_AUTH_RESPONSE)
from .exceptions import ConnectionTimeoutException, HekrAPIException, HekrValueError, DeviceProtocolNotSetException, \
    AuthenticationFailedException
from .helpers import sensitive_info_filter
from .types import MessageID, Action, DeviceCallback, DeviceInfo, \
    AnyCommand, CommandData, DeviceID, EncodedRequest, CommandID

try:
    from typing import NoReturn
except ImportError:
    NoReturn = None

if TYPE_CHECKING:
    from .protocol import Command, Protocol
    from .account import Account

_LOGGER = logging.getLogger(__name__)

ReturnType = TypeVar('ReturnType', Any, NoReturn)


def supports_async_timeout(func: Callable[..., ReturnType]) -> Callable[..., ReturnType]:
    if not asyncio.iscoroutinefunction(func):
        raise ValueError(f'Attempted to decorate non-coroutine method `{func.__name__}`')

    async def wrapper(self: '_BaseConnector', *args, timeout: Optional[int] = None, **kwargs) -> ReturnType:
        if timeout is None:
            timeout = self.timeout

        time_start = time()
        try:
            return await asyncio.wait_for(func(self, *args, **kwargs), timeout=timeout)

        except (asyncio.TimeoutError, asyncio.CancelledError):
            raise ConnectionTimeoutException(
                f'Connector {self} timed out (waited for {round(time()-time_start)} seconds to run `{func.__name__}`)'
            ) from None

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = (func.__doc__ or func.__name__.lower().replace('_', ' ').capitalize()) + \
        '\n:param timeout: (optional) Timeout override in seconds'

    return wrapper


class Response:
    """Processed response class"""
    def __init__(self,
                 state: DeviceResponseState,
                 data: Union[str, Dict[str, Any]],
                 message_id: Optional[MessageID] = None,
                 action: Optional[Action] = None,
                 device: Optional['Device'] = None,
                 command: Optional['Command'] = None,
                 arguments: Optional[Dict[str, Any]] = None,
                 frame_number: Optional[int] = None):
        self._response_timestamp = time()

        self.state = state
        self.data = data
        self.message_id = message_id
        self.action = action
        self.device = device
        self.command = command
        self.arguments = arguments
        self.frame_number = frame_number

    @property
    def response_timestamp(self):
        return self._response_timestamp


class _BaseConnector:
    """Base endpoint class for implementing other endpoints"""

    def __init__(self,
                 application_id: str = DEFAULT_APPLICATION_ID,
                 timeout: float = DEFAULT_TIMEOUT):
        self._last_message_id = None
        self._message_devices = WeakValueDictionary()
        self._attached_devices: List[Device] = list()
        self._application_id = application_id

        self.timeout = timeout

    async def __aenter__(self):
        """
        Async context entrance handler
        Open connection on async context initialisation
        :return: Return current connector object
        """
        await self.open_connection()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Async context exit handler
        :param exc_type:
        :param exc_val:
        :param exc_tb:
        :return:
        """
        if self.is_connected:
            await self.close_connection()

    # internal properties
    @property
    def last_message_id(self) -> Optional[MessageID]:
        """
        Last sent message ID getter
        :return:
        """
        return self._last_message_id

    # attributes and methods to be overridden by inherent connectors
    @property
    def is_authenticated(self) -> bool:
        raise NotImplementedError

    @property
    def is_connected(self) -> bool:
        """
        Get connection state of the connector.
        :return: Connection is open
        """
        raise NotImplementedError

    async def open_connection_without_timeout(self) -> NoReturn:
        """
        Open connection without handling internal timeout

        Overriding methods _must not_ raise exceptions that are caused
        by already open connection, and treat them as successful opens.

        Do not override the wrapper method `open_connection`!
        The wrapper calls this method with support for internal timeout.
        """
        raise NotImplementedError

    async def close_connection_without_timeout(self) -> NoReturn:
        """
        Close connection with connector without handling internal timeout

        Overriding methods _must not_ raise exceptions that are caused
        by already closed connection, and treat them as successful closes.

        Do not override the wrapper method `close_connection`!
        The wrapper calls this method with support for internal timeout.
        """
        raise NotImplementedError

    async def send_request_without_timeout(self, request_str: str) -> NoReturn:
        """
        Send request to device with connector without handling internal timeout

        Do not override the wrapper method `send_request`!
        The wrapper calls this method with support for internal timeout.

        :param request_str: Request payload
        """
        raise NotImplementedError

    async def read_response_without_timeout(self) -> str:
        """
        Read response from connector without handling internal timeout

        Do not override the wrapper method `read_response`!
        The wrapper calls this method with support for internal timeout.

        :return: Response payload on successful read
        """
        raise NotImplementedError

    async def authenticate_without_timeout(self) -> NoReturn:
        """
        Authenticate with connector without handling internal timeout

        Do not override the wrapper method `read_response`!
        The wrapper calls this method with support for internal timeout.
        """
        raise NotImplementedError

    # Timeout wrappers
    @supports_async_timeout
    async def open_connection(self) -> NoReturn:
        """
        Wrapper for connection opener with support for internal timeout

        Do not override this method unless it's a requirement!
        Use the decorator `supports_async_timeout` from this package to enable timeout support.
        """
        if not self.is_connected:
            await self.open_connection_without_timeout()

    @supports_async_timeout
    async def close_connection(self) -> NoReturn:
        """
        Wrapper for connection opener with support for internal timeout

        Do not override this method unless it's a requirement!
        Use the decorator `supports_async_timeout` from this package to enable timeout support.
        """
        if self.is_connected:
            return await self.close_connection_without_timeout()

    @supports_async_timeout
    async def send_request(self, request_str: str) -> NoReturn:
        """
        Wrapper for connection closer with support for internal timeout

        Do not override this method unless it's a requirement!
        Use the decorator `supports_async_timeout` from this package to enable timeout support.
        """
        await self.send_request_without_timeout(request_str)

    @supports_async_timeout
    async def read_response(self) -> str:
        """
        Wrapper for response reader with support for internal timeout

        Do not override this method unless it's a requirement!
        Use the decorator `supports_async_timeout` from this package to enable timeout support.
        """
        return await self.read_response_without_timeout()

    @supports_async_timeout
    async def authenticate(self) -> NoReturn:
        """
        Wrapper for authenticator with support for internal timeout

        Do not override this method unless it's a requirement!
        Use the decorator `supports_async_timeout` from this package to enable timeout support.
        """
        await self.authenticate_without_timeout()

    async def listen_responses(self) -> NoReturn:
        while True:
            print(await self.read_response_without_timeout())

    # Connector device management
    @property
    def devices(self) -> Dict[DeviceID, 'Device']:
        """
        Access devices attached to this connector.
        :return: Dictionary of attached devices indexed by device ID.
        :rtype: Dict[str, 'Device']
        """
        return {hekr_device.device_id: hekr_device for hekr_device in self._attached_devices}

    def attach_device(self, hekr_device: 'Device') -> NoReturn:
        """
        Attach device to connector
        :param hekr_device: Device to attach
        """
        for device in self._attached_devices:
            if device.device_id == hekr_device.device_id:
                raise HekrAPIException(f'Cannot attach device with same device ID')

        self._attached_devices.append(hekr_device)

    def detach_device(self, hekr_device: 'Device') -> NoReturn:
        if hekr_device not in self._attached_devices:
            raise Exception('Cannot detach an unattached device (%s)' % hekr_device)

        self._attached_devices.remove(hekr_device)

    def is_attached(self, hekr_device: 'Device') -> bool:
        """Checks whether device is attached."""
        return hekr_device in self._attached_devices

    @property
    def next_message_id(self) -> int:
        if self._last_message_id is None:
            return 1
        next_message_id = (self._last_message_id % 65535) + 1

        return next_message_id

    def _save_message_id(self, message_id: int, device: Optional['Device'] = None):
        self._last_message_id = message_id

        previous_device: Optional['Device'] = self._message_devices.get(message_id)
        if previous_device is not None:
            # @TODO: find a way to prevent this
            _LOGGER.warning(f'Message ID {message_id} was not processed before, and has device {previous_device} '
                            f'attached to it. Should processing of the older message with the same message ID '
                            'commence, an invalid device might be extracted at the processing stage.')
            del self._message_devices[message_id]

        if device is not None:
            self._message_devices[message_id] = device

    # Request preparation
    def generate_request(self,
                         action: str,
                         params: dict = None,
                         message_id: int = None,
                         hekr_device: Optional['Device'] = None) -> Tuple[MessageID, EncodedRequest]:
        """
        Generate request string (JSON format).

        :param action: Action name (read README.md for discovered actions list)
        :param params: (optional) Parameters array for actions
        :param hekr_device: (optional) Device to generate request for
        :param message_id: (optional) Message id (default: last message id for set connection)
        :return: Message ID, request payload (On successful generation)
        """
        if message_id is None:
            message_id = self.next_message_id

        elif message_id > 65535:
            raise HekrValueError(variable='message_id', expected='0 <= value <= 65535', got=message_id)

        request_dict = {
            "msgId": message_id,
            "action": action,
        }

        if action != ACTION_HEARTBEAT_REQUEST:
            if not hekr_device:
                raise HekrAPIException(f'Device not set for a "{action}" action request')

            if hekr_device.control_key is None:
                raise HekrAPIException(f'Device {hekr_device} does not have a control key set')

            request_dict["params"] = {
                "devTid": hekr_device.device_id,
                "ctrlKey": hekr_device.control_key,
            }

            if action.startswith("app"):
                request_dict["params"]["appTid"] = self._application_id

        if isinstance(params, dict):
            request_dict['params'].update(params)

        try:
            encoded_request = dumps(request_dict)

        except ValueError:
            raise HekrAPIException(f'Failed to encode request: {request_dict}') from None

        self._save_message_id(message_id, hekr_device)

        return message_id, encoded_request

    # Response processing
    def process_response(self, response_str: str) -> Response:
        """
        Handle incoming response packet (decode from existing string).
        :param response_str: Response string
        :return: Response state, response action, response contents, related device
        """
        try:
            # Default data for unknown response gets set here
            data = loads(response_str)

        except JSONDecodeError as e:
            # This is an invalid response; instead of raising an exception, treat the response
            # as unexpected invalid communication artifact.
            _LOGGER.debug(f'Invalid response received (error: {e}): {response_str}')
            return Response(state=DeviceResponseState.INVALID, data=response_str)

        action = data.get('action')
        message_id = data.get('msgId')

        response = Response(
            state=DeviceResponseState.UNKNOWN,
            data=data,
            action=action,
            message_id=message_id,
        )

        # Get response code from response (default to treat as successful)
        response_code = data.get('code', 200)

        device: Optional['Device'] = None

        if message_id in self._message_devices:
            device = self._message_devices[message_id]
            del self._message_devices[message_id]

        elif 'params' in data and 'devTid' in data['params']:
            device = self.devices.get(data['params']['devTid'])

        if action == ACTION_HEARTBEAT_RESPONSE:
            # Handle heartbeat responses
            if response_code == 200:
                _LOGGER.debug(f'Heartbeat executed successfully on connector {self}')
                response.state = DeviceResponseState.SUCCESS

            else:
                _LOGGER.error(f'Heartbeat failed on connector {self}')
                response.state = DeviceResponseState.FAILURE

        elif action in (ACTION_COMMAND_RESPONSE, ACTION_DEVICE_MESSAGE):
            # Handle responses from command requests
            if not device:
                raise HekrAPIException('Device not attached to connector on response: %s' % data)

            if not device.protocol:
                raise DeviceProtocolNotSetException(device=self)

            if response_code == 200:
                response.command, response.arguments, response.frame_number = \
                    device.protocol.decode(data=data['params']['data'])

                _LOGGER.debug('Command executed successfully on device %s'
                              if action == ACTION_COMMAND_RESPONSE else
                              'Received command request for device %s', self)
                response.state = DeviceResponseState.SUCCESS

            else:
                _LOGGER.debug('Command failed on device %s, raw response: %s', self, data)
                response.state = DeviceResponseState.FAILURE

        return response

    # Helper methods
    async def send_heartbeat(self, hekr_device: Optional['Device'] = None) -> int:
        """
        Send heartbeat with connector.
        :param hekr_device: (optional) Device to send heartbeat to
        :return: Message ID
        """
        message_id, request_str = self.generate_request(ACTION_HEARTBEAT_REQUEST, hekr_device=hekr_device)
        await self.send_request_without_timeout(request_str)
        return message_id


class _BaseConnectorActionAuthentication(_BaseConnector, ABC):
    auth_request_action: str = NotImplemented
    auth_response_action: str = NotImplemented
    auth_invalidation_after: int = NotImplemented

    def __init__(self, *args, **kwargs):
        super(_BaseConnectorActionAuthentication, self).__init__(*args, **kwargs)
        self._authenticated = False
        self._last_response_timestamp = 0

    @property
    def is_authenticated(self) -> bool:
        if (self._last_response_timestamp - time()) > self.auth_invalidation_after:
            self._authenticated = False
        return self._authenticated

    async def authenticate_without_timeout(self) -> NoReturn:
        """
        Authenticate with action
        :return:
        """
        _, request_str = self.generate_authentication_request()

        await self.send_request_without_timeout(request_str)

        response_str = await self.read_response_without_timeout()
        response = self.process_response(response_str)

        if response.state != DeviceResponseState.SUCCESS:
            raise AuthenticationFailedException(reason=f'Credentials rejected on connector {self}')

        self._authenticated = True

        _LOGGER.debug('Authentication on %s successful' % self)

    def generate_authentication_request(self, message_id: Optional[int] = None) -> Tuple[MessageID, EncodedRequest]:
        """
        Override in inherent connectors.
        :return:
        """
        return self.generate_request(
            action=self.auth_request_action,
            message_id=message_id
        )

    def process_response(self, response_str: str) -> Response:
        response = super().process_response(response_str)

        if response.state == DeviceResponseState.UNKNOWN and response.action == self.auth_response_action:
            response_code = response.data.get('code')
            if response_code == 200:
                self._authenticated = True
                _LOGGER.debug(f'Successful authentication on connector {self}')
                response.state = DeviceResponseState.SUCCESS
            else:
                self._authenticated = False
                _LOGGER.error(f'Authentication failed due to invalid credentials on connector {self}')
                response.state = DeviceResponseState.FAILURE

        self._last_response_timestamp = time()

        return response


class LocalConnector(_BaseConnectorActionAuthentication):
    """Endpoint via LAN"""

    auth_request_action = ACTION_DEVICE_AUTH_REQUEST
    auth_response_action = ACTION_DEVICE_AUTH_RESPONSE

    class EndpointProtocol(asyncio.DatagramProtocol):
        """Datagram protocol for the endpoint high-level interface."""

        def __init__(self, endpoint):
            self._endpoint = endpoint

        def connection_made(self, transport):
            _LOGGER.debug('Datagram protocol connection established')
            self._endpoint._transport = transport

        def connection_lost(self, exc):
            if exc is not None:  # pragma: no cover
                _LOGGER.warning(f'Endpoint lost the connection: {exc}')
            self._endpoint.close()

        def datagram_received(self, data, addr):
            self._endpoint.feed_datagram(data, addr)

        def error_received(self, exc):
            _LOGGER.error(f'Endpoint received an error: {exc}')

    class Endpoint:
        """High-level interface for UDP remote endpoints.

        It is initialized with an optional queue size for the incoming datagrams.
        """

        def __init__(self, queue_size: Optional[int] = None):
            if queue_size is None:
                queue_size = 0

            self._queue = asyncio.Queue(queue_size)
            self._closed = False
            self._transport = None

        # Protocol callbacks

        def feed_datagram(self, data, addr):
            try:
                self._queue.put_nowait((data, addr))
            except asyncio.QueueFull:
                _LOGGER.warning('Endpoint queue is full')

        def close(self):
            # Manage flag
            if self._closed:
                return
            self._closed = True
            # Wake up
            if self._queue.empty():
                self.feed_datagram(None, None)
            # Close transport
            if self._transport:
                self._transport.close()

        def send(self, data):
            """Send a datagram to the given address."""
            if self._closed:
                raise IOError("Endpoint is closed")
            self._transport.sendto(data, None)

        async def receive(self):
            """Wait for an incoming datagram and return it with
            the corresponding address.

            This method is a coroutine.
            """
            if self._queue.empty() and self._closed:
                raise IOError("Endpoint is closed")

            data, _ = await self._queue.get()
            if data is None:
                raise IOError("Endpoint is closed")

            return data

        def abort(self):
            """Close the transport immediately."""
            if self._closed:
                raise IOError("Endpoint is closed")
            self._transport.abort()
            self.close()

        # Properties

        @property
        def address(self):
            """The endpoint address as a (host, port) tuple."""
            return self._transport.get_extra_info("socket").getsockname()

        @property
        def closed(self):
            """Indicates whether the endpoint is closed or not."""
            return self._closed

    def __init__(self,
                 host: str, port: int,
                 application_id: str = DEFAULT_APPLICATION_ID,
                 timeout: float = DEFAULT_TIMEOUT) -> NoReturn:
        super().__init__(application_id=application_id, timeout=timeout)
        self._transport = None
        self._endpoint: Optional['LocalConnector.Endpoint'] = None
        self._host = host
        self._port = port

    def __str__(self):
        return '<HekrApi:' + self.__class__.__name__ + '(' + self._host + ':' + str(self._port) + ')>'

    @property
    def host(self) -> str:
        """
        Host getter

        :return: Current host
        """
        return self._host

    @host.setter
    def host(self, value: str) -> NoReturn:
        """
        Host setter

        :param value: New host
        """
        if self.is_connected:
            raise HekrAPIException('Forbidden to set host on open connector')
        self._host = value

    @property
    def port(self) -> int:
        """
        Port number getter

        :return: Current port number
        """
        return self._port

    @port.setter
    def port(self, value: int) -> NoReturn:
        """
        Port number setter

        :param value: New port number
        """
        if self.is_connected:
            raise HekrAPIException('Forbidden to set port on open connector')
        self._port = value

    def attach_device(self, hekr_device: 'Device') -> NoReturn:
        """
        Attach single device to local connector.

        :param hekr_device: Device to attach
        :return: Whether operation is successful
        """
        if self._attached_devices:
            raise HekrAPIException('Cannot attach more than one device to a local socket')

        super().attach_device(hekr_device)

    def generate_request(self,
                         action: str,
                         params: dict = None,
                         message_id: int = None,
                         hekr_device: Optional['Device'] = None) -> Tuple[MessageID, EncodedRequest]:
        """
        Generate request to be sent over connector

        :param action:
        :param params:
        :param message_id:
        :param hekr_device:
        :return:
        """
        if not self._attached_devices:
            raise HekrAPIException('No device attached to local connector')

        connector_device = self._attached_devices[0]
        if hekr_device is not None:
            if hekr_device != connector_device:
                raise HekrValueError(variable='hekr_device',
                                     expected=[connector_device, None],
                                     got=hekr_device)

        return super(LocalConnector, self).generate_request(
            action=action,
            params=params,
            message_id=message_id,
            hekr_device=connector_device
        )

    async def open_connection_without_timeout(self) -> NoReturn:
        """
        Open local endpoint without handling internal timeout
        :return:
        """
        if self.is_connected:
            # endpoint is already connected
            return

        loop = asyncio.get_event_loop()

        endpoint = LocalConnector.Endpoint(None)
        await loop.create_datagram_endpoint(
            remote_addr=(self._host, self._port),
            protocol_factory=lambda: LocalConnector.EndpointProtocol(endpoint)
        )
        self._endpoint = endpoint

    async def close_connection_without_timeout(self) -> NoReturn:
        """Close local endpoint"""
        if self._endpoint is None:
            # endpoint was never open
            return

        if self._endpoint.closed:
            # remove the closed endpoint
            self._endpoint = None
            return

        _LOGGER.debug('Closing local endpoint on device %s' % self._attached_devices)
        self._endpoint.close()
        if not self._endpoint.closed:
            raise HekrAPIException('Could not close existing endpoint')

        self._endpoint = None

    async def send_request_without_timeout(self, request_str: str) -> NoReturn:
        """
        Send request without handling internal timeout.

        :param request_str: Request contents
        :return: Operation is successful
        """
        _LOGGER.debug('Sending request via %s with content: %s' % (self, sensitive_info_filter(request_str)))
        try:
            self._endpoint.send(str.encode(request_str))

        except IOError as e:
            raise HekrAPIException(f'IO Error: {e}')

    async def read_response_without_timeout(self) -> str:
        """
        Read response without handling internal timeout
        :return: Response contents
        """
        _LOGGER.debug('Starting receiving on %s' % self)
        try:
            response = await self._endpoint.receive()

        except IOError as e:
            raise HekrAPIException(f'IO Error: {e}') from None

        _LOGGER.debug('Received response on %s with content: %s' % (self, sensitive_info_filter(response)))
        return response.decode('utf-8').strip()

    @property
    def is_connected(self) -> bool:
        return self._endpoint is not None


class CloudConnector(_BaseConnectorActionAuthentication):
    """Endpoint via cloud"""
    auth_request_action = ACTION_DEVICE_AUTH_REQUEST
    auth_response_action = ACTION_DEVICE_AUTH_RESPONSE

    def __init__(self,
                 access_token: Optional[str],
                 application_id: str = DEFAULT_APPLICATION_ID,
                 websocket_host: str = DEFAULT_WEBSOCKET_HOST,
                 websocket_port: int = DEFAULT_WEBSOCKET_PORT,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        super().__init__(
            application_id=application_id,
            timeout=timeout
        )

        self._access_token = access_token
        self._session: Optional[ClientSession] = None
        self._endpoint: Optional['ClientWebSocketResponse'] = None
        self._websocket_host = websocket_host
        self._websocket_port = websocket_port

    def __str__(self) -> str:
        return '<Hekr:' + self.__class__.__name__ + '(' + self._websocket_host + ':' + str(self._websocket_port) + ')>'

    # built-in properties
    @property
    def access_token(self) -> Optional[str]:
        return self._access_token

    @access_token.setter
    def access_token(self, value: str) -> NoReturn:
        """
        Access token setter
        :param value:
        :return:
        """
        self._access_token = value

    @property
    def is_connected(self) -> bool:
        return self._endpoint is not None and self._session is not None

    @property
    def websocket_host(self) -> str:
        return self._websocket_host

    @websocket_host.setter
    def websocket_host(self, value: str) -> NoReturn:
        if self.is_connected:
            raise AttributeError('Forbidden to set websocket host attribute while connection is established')
        self._websocket_host = value

    @property
    def websocket_port(self) -> int:
        return self._websocket_port

    @websocket_port.setter
    def websocket_port(self, value: int) -> NoReturn:
        if self.is_connected:
            raise AttributeError('Forbidden to set websocket port attribute while connection is established')
        self._websocket_port = value

    # Connection handling
    async def open_connection_without_timeout(self) -> NoReturn:
        _LOGGER.debug(f'Opening cloud endpoint to {self._websocket_host}:{self._websocket_port}')
        session = ClientSession()
        try:
            from random import getrandbits
            from base64 import b64encode
            raw_key = bytes(getrandbits(8) for _ in range(16))
            websocket_key = b64encode(raw_key).decode('utf-8')

            self._endpoint = await session.ws_connect(
                'https://' + self._websocket_host + ':' + str(self._websocket_port) + '/',
                headers={
                    'Sec-WebSocket-Key': websocket_key,
                    'Sec-WebSocket-Version': '13',
                    'Connection': 'upgrade',
                    'Upgrade': 'websocket'
                })
            self._session = session
            _LOGGER.debug(f'Cloud endpoint opened to {self._websocket_host}:{self._websocket_port}')

        except client_exceptions.ClientConnectionError:
            await session.close()
            raise HekrAPIException('Client connection could not be established') from None

    async def close_connection_without_timeout(self) -> bool:
        if not self.is_connected:
            return False

        try:
            await self._endpoint.close()
            await self._session.close()

        except BaseException:
            raise HekrAPIException('Exception occurred while trying to close: %s' % self)

        finally:
            self._session = None
            self._endpoint = None

        return True

    async def send_request_without_timeout(self, request_str: str) -> NoReturn:
        try:
            await self._endpoint.send_str(request_str)

        except BaseException as e:
            raise HekrAPIException(f'Exception occurred while sending over socket: {e}')

    async def read_response_without_timeout(self) -> str:
        try:
            message = await self._endpoint.receive()

        except BaseException as e:
            raise HekrAPIException(f'Exception occurred while reading: {e}')

        if message.type == WSMsgType.TEXT:
            response_str = message.data

        elif message.type == WSMsgType.BINARY:
            response_str = message.data.decode('utf-8')

        else:
            raise HekrAPIException('Unknown response from WebSockets: %s' % message)

        return response_str

    def generate_authentication_request(self, message_id: Optional[int] = None) -> Tuple[MessageID, EncodedRequest]:
        if message_id is None:
            message_id = self.next_message_id

        if self._access_token is None:
            raise HekrValueError(variable='token', expected='token string', got=None)

        try:
            encoded_message = dumps({
                "msgId": message_id,
                "action": self.auth_request_action,
                "params": {
                    "appTid": self._application_id,
                    "token": self._access_token
                }
            })
        except ValueError as e:
            raise HekrAPIException(f'Failed to encode cloud authentication request: {e}') from None

        self._save_message_id(message_id)

        return message_id, encoded_message


class Device:
    """Device class for Hekr API"""

    def __init__(self, device_id: DeviceID, control_key: Optional[str] = None, protocol: Optional['Protocol'] = None,
                 device_info: Dict[str, Any] = None, local_connector: Optional[LocalConnector] = None,
                 cloud_connector: Optional['CloudConnector'] = None):
        # generic attributes
        self._device_id: DeviceID = device_id
        self.protocol: Optional['Protocol'] = protocol
        self._control_key: Optional[str] = control_key
        self._device_info = device_info
        self.heartbeat_interval = 30

        self._local_connector: Optional[LocalConnector] = local_connector
        self._cloud_connector: Optional['CloudConnector'] = cloud_connector

        self._callbacks: Dict[Optional[int], List[DeviceCallback]] = dict()

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
            self._local_connector if self._local_connector else 'no connector'
        )

    def __eq__(self, other: 'Device') -> bool:
        """
        Compare device ID to other device's ID.
        :param other: Other device
        :return: Comparison result
        """
        if not isinstance(other, Device):
            raise Exception('Comparison with type "%s" is not implemented' % type(other))
        return self.device_id == other.device_id and self.protocol == other.protocol

    def __hash__(self) -> int:
        """
        Generate hash of the device (primarily for sets).
        :return: Hash of the device ID
        """
        return hash(self.device_id)

    def __getattr__(self, item: str):
        if self.protocol is not None:
            command = self.protocol.get_command(item)
            if command is not None:
                return partial(self.command, command, with_read=True)

        raise AttributeError('Object %s does not have attribute "%s"' % (self, item))

    async def __aenter__(self):
        await self.open_connections()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close_connections()

    # built-in properties
    @property
    def device_id(self) -> DeviceID:
        """
        Device ID accessor.
        :return: Device ID of instance
        """
        return self._device_id

    @property
    def control_key(self) -> Optional[str]:
        return self._control_key

    @control_key.setter
    def control_key(self, value: str) -> NoReturn:
        """
        Control key setter.
        :param value:
        :return:
        """
        self._control_key = value
        
    @property
    def local_connector(self) -> Optional[LocalConnector]:
        """
        Local connector accessor.
        :return: 
        """
        return self._local_connector
    
    @local_connector.setter
    def local_connector(self, value: Optional[LocalConnector]):
        """
        Local connector setter
        :return:
        """
        if self._local_connector is not None and self._local_connector != value:
            raise HekrAPIException('Local connector already attached to device')
        value.attach_device(self)
        self._local_connector = value

    @property
    def cloud_connector(self) -> Optional['CloudConnector']:
        """
        Cloud connector accessor.
        :return: 
        """
        return self._cloud_connector

    @cloud_connector.setter
    def cloud_connector(self, value: Optional['CloudConnector']):
        """
        Cloud connector setter
        :return:
        """
        if self._cloud_connector is not None and self._cloud_connector != value:
            raise HekrAPIException('Cloud connector already attached to device')
        value.attach_device(self)
        self._cloud_connector = value 

    # initializes
    @classmethod
    def using_local(cls, host: Union[str, LocalConnector], port: Optional[int] = None, **kwargs) -> 'Device':
        """
        Create device with pre-generated local connector

        :param host: Local connector host / Pre-made local connector
        :param port: Local connector port number
        :param kwargs: Generic keyword arguments for device initialization
        :return: New device object
        """
        if kwargs.get('local_connector') is not None:
            raise HekrValueError(variable='local_connector',
                                 expected='None, as set via host',
                                 got=kwargs['local_connector'])

        device = cls(**kwargs)

        if isinstance(host, LocalConnector):
            device.cloud_connector = host

        else:
            if port is None:
                if device.protocol is None or device.protocol.default_port is None:
                    raise HekrValueError(variable='port', expected='port number', got=None)
                port = device.protocol.default_port

            device.local_connector = LocalConnector(host=host, port=port)

        return device

    @classmethod
    def using_cloud(cls, account: 'Account', **kwargs):
        """
        Create device with pre-attached cloud connector

        :param account: Account with connector to bind the device to
        :param kwargs: Generic keyword arguments for device initialization
        :return: New device object
        """
        # @TODO: finish this
        if kwargs.get('cloud_connector') is not None:
            raise HekrValueError(variable='cloud_connector',
                                 expected='None, as set via account',
                                 got=kwargs['cloud_connector'])

        print(account)

        raise NotImplementedError

    @classmethod
    def from_device_info(cls, device_info: DeviceInfo, protocols: Optional[Iterable['Protocol']], **kwargs):
        device_id = device_info['devTid']
        control_key = device_info['ctrlKey']

        device = cls(
            device_id=device_id,
            control_key=control_key,
            **kwargs
        )
        device.device_info = device_info
        device.detect_protocol(protocols=protocols, set_detected_protocol=True)

        return device

    # callback management
    @property
    def callbacks(self) -> Mapping[Optional[CommandID], List[DeviceCallback]]:
        """
        Return view on device's callbacks
        :return: View[Command ID => Callback list]
        """
        return MappingProxyType(self._callbacks)

    async def _run_callbacks(self, response: Response) -> NoReturn:
        """
        Run callbacks bound to device.
        :param response: Response object
        """
        # Coroutine-related variables
        callback_coroutines = []
        loop: Optional[asyncio.AbstractEventLoop] = None

        # Collect sections for callbacks
        handle_sections = [None]
        if isinstance(response.data, tuple):
            handle_sections.append(response.data[0].command_id)

        # Handle all-callback coroutines
        for section in handle_sections:
            if section in self._callbacks and self._callbacks[section]:
                if loop is None:
                    loop = asyncio.get_running_loop()
                for callback in self._callbacks[section]:
                    if asyncio.iscoroutinefunction(callback):
                        callback_coroutine = callback(response)

                    else:
                        callback_coroutine = loop.run_in_executor(None, callback, response)

                    callback_coroutines.append(callback_coroutine)

        if callback_coroutines:
            loop.create_task(asyncio.wait(callback_coroutines))

    def _get_callback_category(self, command: Optional[AnyCommand] = None):
        if not (command is None or isinstance(command, int)):
            if self.protocol is None:
                raise HekrValueError(variable='device protocol', expected='Protocol object', got=None)
            command = self.protocol.get_command(command)
            return command.command_id
        return command

    def callback_add(self, callback: DeviceCallback, command: Optional[AnyCommand] = None) -> Callable[[], NoReturn]:
        """
        Add callback to device communication flow.

        The signature of every callback must match the one of `Device._run_callbacks` method.

        :param callback: Callback (coroutine) function
        :param command: (optional) Command to attach callback to
        :return: Remove added callback fro callbacks
        """
        command_id = self._get_callback_category(command)
        callbacks = self._callbacks.setdefault(command_id, [])

        if callback not in callbacks:
            callbacks.append(callback)

        return partial(self.callback_remove, callback, command_id)

    def callback_remove(self, callback: DeviceCallback, command: Optional[AnyCommand] = None) -> NoReturn:
        """
        Remove callback
        :param callback: Callback (coroutine) function
        :param command: (optional) Command to remove callback from
        """
        command_id = self._get_callback_category(command)

        if command_id in self._callbacks and callback in self._callbacks[command_id]:
            self._callbacks[command_id].remove(callback)

        if not self._callbacks[command_id]:
            del self._callbacks[command_id]

    # connection management
    async def open_connections(self) -> NoReturn:
        """Open connection with available connectors."""
        _LOGGER.info(f'Opening all available connections for device {self}')
        local_connector = self._local_connector
        cloud_connector = self._cloud_connector

        if not (local_connector or cloud_connector):
            raise HekrAPIException('Device does not have valid connectors to open')

        tasks = []
        if local_connector is not None:
            tasks.append(local_connector.open_connection())

        if cloud_connector is not None:
            tasks.append(cloud_connector.open_connection())

        await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)

    async def close_connections(self) -> NoReturn:
        """Close open connectors for the device."""
        local_connector = self._local_connector
        cloud_connector = self._cloud_connector

        if not (local_connector or cloud_connector):
            raise HekrAPIException('Device does not have valid connectors to close')

        tasks = []
        if local_connector is not None:
            tasks.append(local_connector.open_connection())

        if cloud_connector is not None:
            tasks.append(cloud_connector.open_connection())

        await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)

    async def authenticate(self) -> NoReturn:
        local_connector = self._local_connector
        cloud_connector = self._cloud_connector

        if not (local_connector or cloud_connector):
            raise HekrAPIException('Device does not have valid connectors to authenticate with')

        if local_connector is not None:
            await local_connector.authenticate()

        if cloud_connector is not None:
            await cloud_connector.authenticate()

    # request management
    async def make_request(self,
                           action: Action,
                           params: dict = None,
                           message_id: Optional[MessageID] = None,
                           with_read: bool = False) -> Union[MessageID, Response]:
        """
        Make request to device.

        :param action: Action name.
        :param params: Request parameters.
        :param message_id: Message ID.
        :param with_read:
        :return: Message ID
        """
        connectors = [self._local_connector, self._cloud_connector]
        successful_connector = None
        for connector in connectors:

            if connector is not None and connector.is_connected:
                message_id, request_str = connector.generate_request(
                    action=action,
                    params=params,
                    hekr_device=self,
                    message_id=message_id
                )

                _LOGGER.debug(f'Composed request for device {self} via connector {connector}, '
                              f'content: {sensitive_info_filter(request_str)}')

                try:
                    await connector.send_request(request_str=request_str)
                    successful_connector = connector
                    break
                except (BaseException, IOError, TimeoutError) as e:
                    _LOGGER.error(f'Failed to send over open local connector: {e}')

        if not successful_connector:
            raise HekrAPIException(f'Failed to perform sending routine on connector(s) {connectors}')

        if with_read:
            return await self._get_response(successful_connector, message_id)

        return message_id

    async def heartbeat(self) -> int:
        """Send heartbeat message

        Keyword Arguments:
            connection_type {DeviceConnectionType} -- Connection type to use (default: {None})

        Raises:
            HeartbeatFailedException: Heartbeat message sending failed
        """
        return await self.make_request(ACTION_HEARTBEAT_REQUEST)

    async def _get_response(self, connector: _BaseConnector, message_id: Optional[MessageID] = None):
        """
        Read response from connector, and process it.
        :param message_id:
        :return:
        """
        if not connector.is_connected:
            raise HekrAPIException(f'Connector {connector} is closed on device {self}')

        response_str = await connector.read_response()

        _LOGGER.debug(f'Received response for device {self}: {sensitive_info_filter(response_str)}')

        response = connector.process_response(response_str)

        # Process callbacks before raising an exception
        if self._callbacks:
            await self._run_callbacks(response)

        if message_id is not None and message_id != response.message_id:
            raise HekrValueError(variable='response message ID', expected=message_id, got=response.message_id)

        return response

    async def get_local_response(self, message_id: Optional[MessageID] = None) -> Response:
        local_connector = self._local_connector
        if local_connector is None:
            raise HekrAPIException(f'Device {self} has no cloud connector attached')

        return await self._get_response(local_connector, message_id=message_id)

    async def get_cloud_response(self, message_id: Optional[MessageID] = None) -> Response:
        """
        Read cloud response from device and process.
        :param message_id:
        :return:
        """
        cloud_connector = self._cloud_connector
        if cloud_connector is None:
            raise HekrAPIException(f'Device {self} has no cloud connector attached')

        return await self._get_response(cloud_connector, message_id=message_id)

    # shorthand request commands
    async def command(self,
                      command: AnyCommand,
                      data: CommandData = None,
                      frame_number: int = None,
                      with_read: bool = False) -> Union[MessageID, Response]:
        """
        Execute device command.
        :param command: Command ID/name/object
        :param data: (optional) Data values for datagram
        :param frame_number: (optional) Frame number
        :param with_read: (optional; default to false) Whether to read response immediately after executing
        :return: Message ID
        """
        if isinstance(command, int):
            if not self.protocol:
                raise DeviceProtocolNotSetException(self)

            command = self.protocol.get_command_by_id(command)

        if isinstance(command, str):
            if not self.protocol:
                raise DeviceProtocolNotSetException(self)

            command = self.protocol.get_command_by_name(command)

        if frame_number is None:
            frame_number = self.__last_frame_number + 1

        self.__last_frame_number = frame_number

        # Preserve encoding type before encode call
        encoding_type = self.protocol.default_encoding_type

        encoded_data = self.protocol.encode(
            data=data,
            command=command,
            frame_number=frame_number,
            encoding_type=encoding_type
        )

        _LOGGER.info(f'Sending command {command.name} on device {self}')

        return await self.make_request(ACTION_COMMAND_REQUEST, {"data": encoded_data}, with_read=with_read)

    # other methods
    def detect_protocol(self,
                        protocols: Iterable['Protocol'],
                        set_detected_protocol: bool = False) -> Optional['Protocol']:
        for protocol in protocols:
            if protocol.compatibility_checker is not None:
                try:
                    if protocol.compatibility_checker(self):
                        if set_detected_protocol:
                            self.protocol = protocol
                        return protocol

                except (KeyError, ValueError, IndexError, AttributeError):
                    pass

    # device info-related accessors
    @property
    def device_info(self) -> Optional[DeviceInfo]:
        """
        Accessor to get device info and raise exception if it is not set.
        :return: Device info, if set
        """
        return self._device_info

    @device_info.setter
    def device_info(self, new_info: DeviceInfo) -> NoReturn:
        """
        Update device info with provided values
        :param new_info: Device info
        """
        if 'devTid' in new_info and new_info['devTid'] != self.device_id:
            raise HekrValueError(variable='new_info',
                                 expected=f'device info for {self.device_id}',
                                 got=f'device info for {new_info["devTid"]}')

        if 'ctrlKey' in new_info:
            self.control_key = new_info['ctrlKey']

        self._device_info = new_info

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
    def wan_address(self) -> Optional[str]:
        return self._device_info_for_property['gis'].get('ip', {}).get('ip')

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

    @property
    def name(self):
        return self._device_info_for_property['name']
