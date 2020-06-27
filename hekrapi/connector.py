"""Connection-related code"""
import asyncio
import logging
from _weakrefset import WeakSet
from abc import ABC
from datetime import datetime
from json import dumps, loads, JSONDecodeError
from time import time
from typing import TypeVar, Any, Callable, Optional, Dict, List, TYPE_CHECKING, Tuple, Union

from aiohttp import WSMsgType, client_exceptions, ClientSession, ClientWebSocketResponse

from hekrapi.const import ACTION_DEVICE_AUTH_REQUEST, ACTION_DEVICE_AUTH_RESPONSE, DEFAULT_WEBSOCKET_HOST, \
    DEFAULT_APPLICATION_ID, DEFAULT_WEBSOCKET_PORT, DEFAULT_TIMEOUT, ACTION_HEARTBEAT_REQUEST, \
    ACTION_HEARTBEAT_RESPONSE, ACTION_COMMAND_RESPONSE, ACTION_DEVICE_MESSAGE, ACTION_CLOUD_AUTH_REQUEST, \
    ACTION_CLOUD_AUTH_RESPONSE
from hekrapi.types import MessageID, Action, DeviceID, EncodedRequest, ResponseCallback
from .enums import DeviceResponseState
from .exceptions import ConnectorNotConnectedException, ConnectorUnexpectedMessageIDException, ConnectorError, \
    ConnectorCouldNotConnectException, ConnectorOpenAttributeOverrideException, ConnectorTimeoutException, \
    ConnectorException, ConnectorDeviceCollisionException, DeviceProtocolNotSetException, \
    ConnectorDeviceNotAttachedException, ConnectorDeviceNotProvidedException, ConnectorAuthenticationError, \
    ConnectorSingleDeviceException, ConnectorSendError, ConnectorReadError
from .helpers import sensitive_info_filter

try:
    from typing import NoReturn
except ImportError:
    NoReturn = None

if TYPE_CHECKING:
    from .device import Device
    from .protocol import Command

_LOGGER = logging.getLogger(__name__)

ReturnType = TypeVar('ReturnType', Any, NoReturn)


def supports_async_timeout(func: Callable[..., ReturnType]) -> Callable[..., ReturnType]:
    if not asyncio.iscoroutinefunction(func):
        raise ValueError(f'Attempted to decorate non-coroutine method `{func.__name__}`')

    async def wrapper(connector, *args, timeout: Optional[float] = None, **kwargs):
        if timeout is None:
            timeout = connector.timeout

        try:
            return await asyncio.wait_for(func(connector, *args, **kwargs), timeout=timeout)

        except asyncio.TimeoutError:
            raise ConnectorTimeoutException(connector, func.__name__)

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = (func.__doc__ or func.__name__.lower().replace('_', ' ').capitalize()) + \
        '\n:param timeout: (optional) Timeout override in seconds'

    return wrapper


class Response:
    """Processed response class"""
    def __init__(self,
                 original: str,
                 state: DeviceResponseState = DeviceResponseState.INVALID,
                 decoded: Optional[Dict[str, Any]] = None,
                 message_id: Optional[MessageID] = None,
                 action: Optional[Action] = None,
                 device: Optional['Device'] = None,
                 command: Optional['Command'] = None,
                 arguments: Optional[Dict[str, Any]] = None,
                 frame_number: Optional[int] = None) -> NoReturn:
        self._response_timestamp = time()

        self.original = original
        self.state = state
        self.decoded = decoded
        self.message_id = message_id
        self.action = action
        self.device = device
        self.command = command
        self.arguments = arguments
        self.frame_number = frame_number

    def __repr__(self) -> str:
        return '<Hekr:{} [state={}, device={}, length={}>'.format(
            self.__class__.__name__,
            self.state,
            self.device,
            len(self.original),
        )

    def __str__(self) -> str:
        """Shortcut to return original response"""
        return self.original

    def view(self) -> str:
        return self.__class__.__name__ + f' ({datetime.fromtimestamp(self._response_timestamp)}):\n  ' + '\n  '.join([
            '%s: %s' % (key, ('\n    ' + '\n    '.join([
                '%s: %s' % (arg, val)
                for arg, val in value.items()
            ]) if value else None) if key == 'arguments' else value)
            for key, value in self.__dict__.items()
            if key != '_response_timestamp'
        ])

    def __len__(self) -> int:
        """Shortcut to return response length"""
        return len(self.original)

    @property
    def response_timestamp(self) -> float:
        return self._response_timestamp


class _BaseConnector:
    """Base endpoint class for implementing other endpoints"""

    auth_invalidation_after: float = NotImplemented

    def __init__(self,
                 host: str,
                 port: int,
                 application_id: str = DEFAULT_APPLICATION_ID,
                 timeout: float = DEFAULT_TIMEOUT) -> NoReturn:
        self._last_message_id = None
        self._attached_devices: List[Device] = list()
        self._application_id = application_id
        self._host = host
        self._port = port
        self._authenticated = False
        self._last_response_timestamp = None
        self._last_request_timestamp = None
        self._future_connection_lost: Optional[asyncio.Future] = None

        self.timeout = timeout

    def __str__(self) -> str:
        return 'Hekr:{}({}:{})'.format(
            self.__class__.__name__,
            self._host,
            self._port
        )

    def __repr__(self) -> str:
        return '<Hekr:{} [host={}, port={}]>'.format(
            self.__class__.__name__,
            self._host,
            self._port
        )

    async def __aenter__(self) -> '_BaseConnector':
        """
        Async context entrance handler
        Open connection on async context initialisation
        :return: Return current connector object
        """
        await self.open_connection()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> NoReturn:
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
    def is_connected(self) -> bool:
        """
        Get connection state of the connector.
        :return: Connection is open
        """
        future = self._future_connection_lost
        return not (future is None or future.done())

    @property
    def future_connection_lost(self) -> Optional[asyncio.Future]:
        return self._future_connection_lost

    @property
    def is_authenticated(self) -> bool:
        if not self.is_connected:
            self._authenticated = False
        elif self._last_request_timestamp is not None:
            if (self._last_request_timestamp - time()) > self.auth_invalidation_after:
                self._authenticated = False
        return self._authenticated

    @property
    def last_message_id(self) -> Optional[MessageID]:
        """
        Last sent message ID getter
        :return:
        """
        return self._last_message_id

    @property
    def host(self) -> str:
        """Current host getter"""
        return self._host

    @host.setter
    def host(self, value: str) -> NoReturn:
        """
        New host setter
        :param value: New host
        :raises
        """
        if self.is_connected:
            raise ConnectorOpenAttributeOverrideException(self, 'host')
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
            raise ConnectorOpenAttributeOverrideException(self, 'port')
        self._port = value

    # attributes and methods to be overridden by inherent connectors
    async def _acknowledge_response(self, response: 'Response') -> NoReturn:
        """Acknowledge response retrieved after reading data and processing command"""
        pass

    async def _internal_open_connection(self) -> NoReturn:
        """
        Open connection without handling internal timeout

        Overriding methods _must not_ raise exceptions that are caused by
        connection being already open, and treat them as successful opens.
        """
        raise NotImplementedError

    async def _internal_close_connection(self) -> NoReturn:
        """
        Close connection with connector without handling internal timeout

        Overriding methods _must not_ raise exceptions that are caused by
        connection being already closed, and treat them as successful closes.
        """
        raise NotImplementedError

    async def _internal_send_request(self, request_str: str) -> NoReturn:
        """
        Send request to device with connector without handling internal timeout
        :param request_str: Request payload
        """
        raise NotImplementedError

    async def _internal_read_response(self) -> str:
        """
        Read response from connector without handling internal timeout.
        :return: Response payload on successful read
        """
        raise NotImplementedError

    async def _internal_authenticate(self) -> NoReturn:
        """
        Authenticate with connector without handling internal timeout
        :raises ConnectorAuthenticationError: Authentication failed
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
            await self._internal_open_connection()

    @supports_async_timeout
    async def close_connection(self) -> NoReturn:
        """
        Wrapper for connection closer with support for internal timeout

        Do not override this method unless it's a requirement!
        Use the decorator `supports_async_timeout` from this package to enable timeout support.
        """
        if self.is_connected:
            return await self._internal_close_connection()

    @supports_async_timeout
    async def send_request(self, request_str: str) -> NoReturn:
        """
        Wrapper for request sender with support for internal timeout

        Do not override this method unless it's a requirement!
        Use the decorator `supports_async_timeout` from this package to enable timeout support.
        """
        if not self.is_connected:
            raise ConnectorNotConnectedException(self)

        await self._internal_send_request(request_str)
        self._last_request_timestamp = time()

    @supports_async_timeout
    async def read_response(self) -> str:
        """
        Wrapper for response reader with support for internal timeout

        Do not override this method unless it's a requirement!
        Use the decorator `supports_async_timeout` from this package to enable timeout support.
        """
        if not self.is_connected:
            raise ConnectorNotConnectedException(self)

        response_str = await self._internal_read_response()
        _LOGGER.debug(f'Received response for device {self}: {sensitive_info_filter(response_str)}')
        return response_str

    @supports_async_timeout
    async def acknowledge_response(self, response: Response) -> NoReturn:
        await self._acknowledge_response(response)

    async def get_response(self, message_id: Optional[int] = None, timeout: Optional[float] = None) -> Response:
        if not self.is_connected:
            raise ConnectorNotConnectedException(self)

        response_str = await self.read_response(timeout=timeout)

        _LOGGER.debug(f'Received response for device {self}: {sensitive_info_filter(response_str)}')
        response = self.process_response(response_str)

        if not await self._acknowledge_response(response):
            if not (message_id is None or response.message_id == message_id):
                raise ConnectorUnexpectedMessageIDException(self, response.message_id, message_id)

        if response.device is not None:
            # Process callbacks before raising an exception
            await response.device.run_callbacks(response)

            if message_id is not None and message_id != response.message_id:
                raise ConnectorUnexpectedMessageIDException(self, message_id, response.message_id)

        return response

    async def make_request(self,
                           action: Action,
                           params: dict = None,
                           message_id: Optional[MessageID] = None,
                           with_read: bool = False,
                           hekr_device: Optional['Device'] = None,
                           automatic_authentication: bool = True,
                           timeout_per_request: Optional[float] = None) -> Union[MessageID, 'Response']:
        """

        :param action:
        :param params:
        :param message_id:
        :param with_read:
        :param hekr_device:
        :param automatic_authentication:
        :param timeout_per_request:
        :return:
        """
        if not self.is_connected:
            raise ConnectorNotConnectedException(self)

        message_id, request_str = self.generate_request(
            action=action,
            params=params,
            device=hekr_device,
            message_id=message_id
        )

        _LOGGER.debug(f'Composed request via connector {self}, content: {sensitive_info_filter(request_str)}')

        if not self.is_authenticated:
            if automatic_authentication:
                await self.authenticate(timeout=timeout_per_request)
            else:
                _LOGGER.warning('Request will be sent unauthenticated. This may cause issues.')

        await self.send_request(request_str=request_str, timeout=timeout_per_request)

        if with_read:
            return await self.get_response(message_id, timeout=timeout_per_request)

        return message_id

    @supports_async_timeout
    async def authenticate(self) -> NoReturn:
        """
        Wrapper for authenticator with support for internal timeout

        Do not override this method unless it's a requirement!
        Use the decorator `supports_async_timeout` from this package to enable timeout support.
        """
        if not self.is_connected:
            raise ConnectorNotConnectedException(self)

        await self._internal_authenticate()

    @supports_async_timeout
    async def heartbeat(self) -> MessageID:
        """Wrapper for heartbeats with support for internal timeout"""
        if not self.is_connected:
            raise ConnectorNotConnectedException(self)

        message_id, heartbeat_request = self.generate_request(ACTION_HEARTBEAT_REQUEST)
        await self._internal_send_request(heartbeat_request)
        return message_id

    # Common task helpers
    async def listener_runner(self,
                              callback: Optional[Union[ResponseCallback, Callable[[str], Any]]] = None,
                              raw_responses: bool = False,
                              close_on_exist: bool = True,
                              gap_before_heartbeat: float = 1.5) -> NoReturn:
        """
        Listen to responses and feed them to callback function.
        :param gap_before_heartbeat:
        :param callback:
        :param raw_responses:
        :param close_on_exist:
        :return:
        """
        callback_exists = callable(callback)
        try:
            while True:
                try:
                    if not self.is_connected:
                        await self.open_connection()

                    if not self.is_authenticated:
                        await self.authenticate()

                    invalidate_at = self._last_request_timestamp + self.auth_invalidation_after - gap_before_heartbeat
                    invalidate_remaining = invalidate_at - time()

                    if invalidate_remaining < gap_before_heartbeat:
                        await self.heartbeat()
                        invalidate_remaining = self._last_request_timestamp - time() + self.auth_invalidation_after

                    try:
                        response = await asyncio.wait_for(self._internal_read_response(), invalidate_remaining)
                    except asyncio.TimeoutError:
                        continue

                    if not raw_responses:
                        response = self.process_response(response)

                except ConnectorException as e:
                    _LOGGER.error('Error on connector %s: %s' % (self, e))
                    continue

                loop = None
                if callback_exists:
                    loop = asyncio.get_running_loop()
                    if asyncio.iscoroutinefunction(callback):
                        loop.create_task(callback(response))
                    else:
                        loop = asyncio.get_running_loop()
                        loop.run_in_executor(None, callback, response)

                if not raw_responses and response.device:
                    for device in self._attached_devices:
                        if device.device_id == response.device.device_id:
                            # Run callbacks for found device
                            if loop is None:
                                loop = asyncio.get_running_loop()
                            loop.create_task(device.run_callbacks(response))

        except asyncio.CancelledError:
            pass
        finally:
            if close_on_exist:
                await self.close_connection()

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
                if device == hekr_device:
                    return
                raise ConnectorDeviceCollisionException(self, device.device_id)

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

    # Request preparation
    def generate_request_params(self,
                                action: str,
                                params: Dict[str, Any] = None,
                                hekr_device: Optional['Device'] = None) -> Optional[Dict[str, Any]]:
        """
        Generate request parameters.
        Can technically be easily overridden in inherent connector classes.
        :param action: Request action
        :param params: Provided params (may be overriding)
        :param hekr_device: (optional) Hekr device to use in request
        :return: Request params, or None if not required
        """
        request_params = dict()
        if action != ACTION_HEARTBEAT_REQUEST:
            if hekr_device:
                request_params["devTid"] = hekr_device.device_id

                control_key = hekr_device.control_key
                if control_key is not None:
                    request_params["ctrlKey"] = control_key

                if action.startswith("app"):
                    request_params["appTid"] = self._application_id

            elif not params.get("devTid"):
                raise ValueError(f'device or device ID not set for a "{action}" action request')

            if params is not None:
                request_params.update(params)
            return request_params

        elif params:
            raise ValueError(f"parameters are unsupported with '{action}' action")

        return None

    def generate_request(self,
                         action: str,
                         params: Dict[str, Any] = None,
                         message_id: int = None,
                         device: Optional['Device'] = None) -> Tuple[MessageID, EncodedRequest]:
        """
        Generate request string (JSON format).

        :param action: Action name (read README.md for discovered actions list)
        :param params: (optional) Parameters array for actions
        :param device: (optional) Device to generate request for
        :param message_id: (optional) Message id (default: last message id for set connection)
        :return: Message ID, request payload (On successful generation)
        """
        if message_id is None:
            message_id = self.next_message_id

        elif message_id not in range(1, 65536):
            raise ValueError('invalid message id (out of bounds: 0 < message ID < 65536)')

        request_dict = {
            "msgId": message_id,
            "action": action,
        }

        request_params = self.generate_request_params(action, params, device)
        if request_params is not None:
            request_dict["params"] = request_params

        encoded_request = dumps(request_dict)

        self._last_message_id = message_id

        return message_id, encoded_request

    # Response processing
    def process_response(self, response_str: str) -> Response:
        """
        Handle incoming response packet (decode from provided JSON string source).
        :param response_str: Response string
        :return: Response state, response action, response contents, related device
        """
        response = Response(original=response_str)
        try:
            # Default data for unknown response gets set here
            decoded = loads(response_str)

        except JSONDecodeError as e:
            # This is an invalid response; instead of raising an exception, treat the response
            # as unexpected invalid communication artifact.
            _LOGGER.error(f'Invalid response received (error: {e}): {sensitive_info_filter(response_str)}')
            return response

        action = decoded.get('action')
        message_id = decoded.get('msgId')

        response.state = DeviceResponseState.UNKNOWN
        response.decoded = decoded
        response.action = action
        response.message_id = message_id

        # Get response code from response (default to treat as successful)
        response_code = decoded.get('code', 200)

        device: Optional['Device'] = None

        if 'params' in decoded and 'devTid' in decoded['params']:
            device_id = decoded['params']['devTid']
            device: Optional['Device'] = None

            for attached_device in self._attached_devices:
                if attached_device.device_id == device_id:
                    device = attached_device
                    break

            if device is None:
                raise ConnectorDeviceNotAttachedException(self, device_id)

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
            if device is None:
                raise ConnectorDeviceNotProvidedException(self)

            protocol = device.protocol
            if not protocol:
                raise DeviceProtocolNotSetException(self)

            if response_code == 200:
                response.command, response.arguments, response.frame_number = \
                    device.protocol.decode(data=decoded['params']['data'])

                _LOGGER.debug(('Command executed successfully on device %s'
                               if action == ACTION_COMMAND_RESPONSE else
                               'Received command request for device %s') % device)
                response.state = DeviceResponseState.SUCCESS

            else:
                _LOGGER.debug('Command failed on device %s, raw response: %s' % (device, decoded))
                response.state = DeviceResponseState.FAILURE

        response.device = device

        return response


class _BaseConnectorActionAuthentication(_BaseConnector, ABC):
    """Connector base that authenticates by sending / receiving actions"""

    auth_request_action: str = NotImplemented
    auth_response_action: str = NotImplemented

    async def _internal_authenticate(self) -> NoReturn:
        """
        Authenticate with action
        :return:
        """
        _, request_str = self.generate_authentication_request()

        await self._internal_send_request(request_str)

        response_str = await self._internal_read_response()
        response = self.process_response(response_str)

        if response.state != DeviceResponseState.SUCCESS:
            # @TODO: manipulate codes
            _LOGGER.debug('response: %s' % response.view())
            raise ConnectorAuthenticationError(self)

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
            response_code = response.decoded.get('code')
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


class _LocalEndpointConnector(_BaseConnector, ABC):
    """Endpoint via LAN"""

    auth_request_action = ACTION_DEVICE_AUTH_REQUEST
    auth_response_action = ACTION_DEVICE_AUTH_RESPONSE
    auth_invalidation_after = 30.0

    def __init__(self, *args, **kwargs) -> NoReturn:
        super().__init__(*args, **kwargs)
        self._transport = None
        self._endpoint: Optional['_LocalEndpointConnector.Endpoint'] = None

    # attached device management
    def attach_device(self, hekr_device: 'Device') -> NoReturn:
        """
        Attach single device to local connector.

        :param hekr_device: Device to attach
        :return: Whether operation is successful
        """
        if self._attached_devices:
            raise ConnectorSingleDeviceException(self, self.attached_device)

        super().attach_device(hekr_device)

    @property
    def attached_device(self) -> Optional['Device']:
        """Get single attached device."""
        if self._attached_devices:
            return self._attached_devices[0]

    # request generation
    def generate_request(self, action: str, params: dict = None, message_id: int = None,
                         device: Optional['Device'] = None) -> Tuple[MessageID, EncodedRequest]:
        """
        Generate request to be sent over connector

        :param action:
        :param params:
        :param message_id:
        :param device:
        :return:
        """
        connector_device = self.attached_device
        if connector_device is None:
            raise ConnectorDeviceNotAttachedException('No device attached to local connector')

        if device is not None:
            if device != connector_device:
                raise ConnectorSingleDeviceException(self, connector_device)

        return super(_LocalEndpointConnector, self).generate_request(
            action=action,
            params=params,
            message_id=message_id,
            device=connector_device
        )

    # connection management
    async def _internal_open_connection(self) -> Optional[asyncio.Future]:
        """
        Open local endpoint without handling internal timeout
        :return: Future object
        """
        if self.is_connected:
            # endpoint is already connected
            return None

        loop = asyncio.get_event_loop()

        fut_conn_lost = loop.create_future()
        fut_conn_made = loop.create_future()

        endpoint = LocalConnector.Endpoint(None)

        await loop.create_datagram_endpoint(
            remote_addr=(self._host, self._port),
            protocol_factory=lambda: _LocalEndpointConnector.EndpointProtocol(
                endpoint,
                fut_conn_made,
                fut_conn_lost
            )
        )

        result = await fut_conn_made
        if result is False:
            if fut_conn_lost.done():
                exception = fut_conn_lost.exception()
                if exception:
                    raise ConnectorCouldNotConnectException(self, exception)
            raise ConnectorCouldNotConnectException(self, 'unknown, check logs')
        else:
            _LOGGER.debug('Connection made on connector %s' % self)

        self._endpoint = endpoint
        self._future_connection_lost = fut_conn_lost

    async def _internal_close_connection(self) -> NoReturn:
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
        self._endpoint = None

    async def _internal_send_request(self, request_str: str) -> NoReturn:
        """
        Send request without handling internal timeout.

        :param request_str: Request contents
        :return: Operation is successful
        """
        _LOGGER.debug('Sending request via %s with content: %s' % (self, sensitive_info_filter(request_str)))
        try:
            self._endpoint.send(str.encode(request_str))

        except IOError as e:
            if self._future_connection_lost.done():
                conn_exc = self._future_connection_lost.exception()
                if conn_exc:
                    # Raise real cause of error, if present
                    raise ConnectorError(self, conn_exc) from None
            raise ConnectorError(self, e) from None

    async def _internal_read_response(self) -> str:
        """
        Read response without handling internal timeout
        :return: Response contents
        """
        _LOGGER.debug('Start receiving on %s' % self)
        try:
            response = await self._endpoint.receive()

        except IOError as e:
            if self._future_connection_lost.done():
                conn_exc = self._future_connection_lost.exception()
                if conn_exc:
                    # Raise real cause of error, if present
                    raise ConnectorError(self, conn_exc) from None
            raise ConnectorError(self, e) from None

        response_str = response.decode('utf-8').strip()

        _LOGGER.debug('Received response on %s with content: %s' % (self, sensitive_info_filter(response_str)))

        return response_str

    class EndpointProtocol(asyncio.DatagramProtocol):
        """Datagram protocol for the endpoint high-level interface."""

        def __init__(self,
                     endpoint: '_LocalEndpointConnector.Endpoint',
                     fut_conn_made: asyncio.Future,
                     fut_conn_lost: asyncio.Future):
            self._endpoint = endpoint
            self._future_connection_made = fut_conn_made
            self._future_connection_lost = fut_conn_lost

        def connection_made(self, transport):
            _LOGGER.debug('Datagram protocol connection established')
            self._endpoint._transport = transport
            self._future_connection_made.set_result(True)

        def _close_endpoint(self, exc):
            if not self._future_connection_lost.done():
                if exc is None:
                    self._future_connection_lost.set_result(True)
                else:
                    self._future_connection_lost.set_exception(exc)

            if not self._future_connection_made.done():
                self._future_connection_made.set_result(False)

            self._endpoint.close()

        def connection_lost(self, exc):
            if exc is not None:  # pragma: no cover
                _LOGGER.warning(f'Endpoint lost the connection: {exc}')

            self._close_endpoint(exc)

        def datagram_received(self, data, addr):
            self._endpoint.feed_datagram(data, addr)

        def error_received(self, exc):
            _LOGGER.error(f'Endpoint received an error: {exc}')
            if isinstance(exc, ConnectionRefusedError):
                self._close_endpoint(exc)

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
            self._error_futures = WeakSet()

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


class LocalConnector(_LocalEndpointConnector, _BaseConnectorActionAuthentication):
    pass


class CloudConnector(_BaseConnectorActionAuthentication):
    """Endpoint via cloud"""
    auth_request_action = ACTION_CLOUD_AUTH_REQUEST
    auth_response_action = ACTION_CLOUD_AUTH_RESPONSE
    auth_invalidation_after = 30.0

    def __init__(self,
                 host: str = DEFAULT_WEBSOCKET_HOST,
                 port: int = DEFAULT_WEBSOCKET_PORT,
                 access_token: Optional[str] = None, **kwargs):
        super().__init__(host, port, **kwargs)

        self._access_token = access_token
        self._session: Optional[ClientSession] = None
        self._endpoint: Optional['ClientWebSocketResponse'] = None

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

    # Connection handling
    async def _internal_open_connection(self) -> NoReturn:
        _LOGGER.debug(f'Opening cloud endpoint to {self._host}:{self._port}')
        session = ClientSession()
        try:
            from random import getrandbits
            from base64 import b64encode
            raw_key = bytes(getrandbits(8) for _ in range(16))
            websocket_key = b64encode(raw_key).decode('utf-8')

            self._endpoint = await session.ws_connect(
                'https://' + self._host + ':' + str(self._port) + '/',
                headers={
                    'Sec-WebSocket-Key': websocket_key,
                    'Sec-WebSocket-Version': '13',
                    'Connection': 'upgrade',
                    'Upgrade': 'websocket'
                })
            self._session = session
            _LOGGER.debug(f'Cloud endpoint opened to {self._host}:{self._port}')

        except client_exceptions.ClientConnectionError as e:
            await session.close()
            raise ConnectorCouldNotConnectException(self, e)

    async def _internal_close_connection(self) -> NoReturn:
        if not self.is_connected:
            return

        try:
            await self._endpoint.close()
            await self._session.close()

        except BaseException as e:
            _LOGGER.error('Exception occurred while trying to close %s: %s' % (self, e))

        finally:
            self._session = None
            self._endpoint = None

    async def _internal_send_request(self, request_str: str) -> NoReturn:
        try:
            await self._endpoint.send_str(request_str)

        except BaseException as e:
            raise ConnectorSendError(self, e) from None

    async def _internal_read_response(self) -> str:
        try:
            message = await self._endpoint.receive()

        except BaseException as e:
            raise ConnectorReadError(self, e) from None

        if message.type == WSMsgType.TEXT:
            response_str = message.data

        elif message.type == WSMsgType.BINARY:
            response_str = message.data.decode('utf-8')

        else:
            raise ConnectorReadError(self, "unsupported response type")

        return response_str

    def generate_authentication_request(self, message_id: Optional[int] = None) -> Tuple[MessageID, EncodedRequest]:
        if message_id is None:
            message_id = self.next_message_id

        if self._access_token is None:
            raise ValueError("expected authentication on account")

        encoded_message = dumps({
            "msgId": message_id,
            "action": self.auth_request_action,
            "params": {
                "appTid": self._application_id,
                "token": self._access_token
            }
        })

        self._last_message_id = message_id

        return message_id, encoded_message
