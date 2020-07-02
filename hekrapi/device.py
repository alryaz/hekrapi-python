# -*- coding: utf-8 -*-
"""Device class module for Hekr API"""
__all__ = [
    'Device',
    'DeviceInfo',
    'DeviceType'
]
import asyncio
import logging
from functools import partial
from types import MappingProxyType
from typing import Optional, Any, TYPE_CHECKING, Dict, Callable, List, Union, Iterable, \
    Mapping, Type, Sequence, Generator

from hekrapi.connector import BaseCloudConnector, BaseDirectConnector
from hekrapi.const import ACTION_HEARTBEAT_REQUEST, ACTION_COMMAND_REQUEST
from hekrapi.enums import DeviceType, WorkMode
from hekrapi.exceptions import DeviceProtocolNotSetException, DeviceConnectorsMissingException, \
    DeviceConnectorsNotConnectedException, \
    DeviceConnectorMissingException
from hekrapi.helpers import create_callback_task
from hekrapi.protocol import Protocol
from hekrapi.types import MessageID, Action, ResponseCallback, \
    AnyCommand, CommandData, DeviceID, CommandID, DeviceInfo

if TYPE_CHECKING:
    from hekrapi.protocol import Command
    from hekrapi.connector import BaseConnector, Response

_LOGGER = logging.getLogger(__name__)


class ConnectorManager(Sequence):
    def __init__(self, device: 'Device', connectors: Optional[Sequence['BaseConnector']] = None):
        self._device = device
        self._connectors: List['BaseConnector'] = list() if connectors is None else list(connectors)

    def __len__(self) -> int:
        return self._connectors.__len__()

    def __getitem__(self, item: Union[int, slice]):
        return self._connectors.__getitem__(item)

    def __iter__(self):
        return self._connectors.__iter__()

    def filtered(self, connected: Optional[bool] = None,
                 authenticated: Optional[bool] = None) -> Generator['BaseConnector', Any, None]:
        for connector in self._connectors:
            if not (connected is None or connector.is_connected is connected):
                continue
            if not (authenticated is None or connector.is_authenticated is authenticated):
                continue
            yield connector

    def first_connected(self, connected: bool = True) -> Optional['BaseConnector']:
        for connector in self.filtered(connected=connected):
            return connector

    def first_authenticated(self, authenticated: bool = True) -> Optional['BaseConnector']:
        for connector in self.filtered(connected=authenticated):
            return connector


class DeviceInfo(dict):
    def __init__(self, device_info_source: Mapping[str, Any], check_source: bool = False, **kwargs):
        """Device info initializer"""
        if check_source:
            self.validate_source_dictionary(device_info_source)
        super().__init__(device_info_source, **kwargs)

    def __str__(self):
        return '{}({})'.format(
            self.__class__.__name__,
            self.device_id,
        )

    def __repr__(self):
        return '<Hekr:{}[device_id={}, device_type={}]>'.format(
            self.__class__.__name__,
            self.device_id,
            self.device_type.name,
        )

    @classmethod
    def validate_source_dictionary(cls, device_info_source: Mapping[str, Any], raise_for_error: bool = False) -> bool:
        for key, value in cls.__dict__.items():
            if isinstance(value, property):
                try:
                    print(key, value.__get__(device_info_source))
                except (IndexError, KeyError, AttributeError):
                    if raise_for_error:
                        return False
                    raise
        return True

    def detect_protocol(self, protocols: Sequence['Protocol']) -> Optional['Protocol']:
        """
        Check whether device info is compatible with any protocol within the list, and return the protocol if true.
        :param protocols: Iterable object of protocols (classes)
        :return: Protocol class, if found
        """
        for protocol in protocols:
            if protocol.is_device_info_compatible(self):
                return protocol

    @property
    def device_type(self) -> DeviceType:
        """Device type getter"""
        return DeviceType(self['devType'])

    @property
    def work_mode(self) -> WorkMode:
        """Device work mode getter"""
        return WorkMode(self['workModeType'])

    @property
    def device_id(self) -> str:
        """Device ID getter"""
        return self['devTid']

    @property
    def product_id(self) -> str:
        """Product ID getter"""
        return self['mid']

    @property
    def control_key(self) -> str:
        """Control key getter"""
        return self['ctrlKey']

    @property
    def product_name(self) -> str:
        """Product name getter"""
        return self['productName']['en_US']

    @property
    def category_name(self) -> str:
        """Product category name getter"""
        return self['categoryName']['en_US']

    @property
    def sdk_version(self) -> str:
        """Firmware SDK version getter"""
        return self['sdkVer']

    @property
    def firmware_version(self) -> str:
        """Firmware build version getter"""
        return self['binVersion']

    @property
    def url_logo(self) -> str:
        """Device icon/logo URL getter"""
        return self['logo']

    @property
    def mac_address(self) -> Optional[str]:
        """Device MAC-address getter"""
        return self.get('mac')

    @property
    def lan_address(self) -> Optional[str]:
        """Device LAN IP address getter"""
        return self.get('lanIp')

    @property
    def wan_address(self) -> Optional[str]:
        """Device WAN IP address getter"""
        return self.get('gis', {}).get('ip', {}).get('ip')

    @property
    def is_online(self) -> bool:
        """Online status getter"""
        return self.get('online', False)

    @property
    def rssi(self) -> Optional[int]:
        """Wireless connection strength getter"""
        return self.get('rssi')

    @property
    def bind_key(self) -> Optional[str]:
        """Bind key getter"""
        return self.get('bindKey')

    @property
    def device_name(self) -> str:
        """Device name getter"""
        return self['deviceName']

    @property
    def name(self) -> str:
        """User-assigned device name getter"""
        return self['name']

    @property
    def cloud_connect_host(self) -> Optional[str]:
        """Cloud connection host getter"""
        return self.get('dcInfo', {}).get('connectHost')


class Device:
    """Device class for Hekr API"""

    def __init__(self,
                 device_id: Union[DeviceID, DeviceInfo],
                 control_key: Optional[str] = None,
                 protocol: Optional[Type['Protocol']] = None):
        device_info = None
        if isinstance(device_id, DeviceInfo):
            device_info = device_id
            device_id = device_info.device_id
            if control_key is None:
                control_key = device_info.control_key

        self._device_id: DeviceID = device_id
        self._device_info: Optional[DeviceInfo] = device_info
        self._control_key: Optional[str] = control_key
        self._callbacks: Dict[Optional[int], List[ResponseCallback]] = dict()
        self._last_frame_number = 0
        self._direct_connector = None
        self._cloud_connector = None

        self._protocol = protocol

    def __str__(self) -> str:
        """
        Generates a string representation of the device
        :return: String representation (human-readable)
        """

        return 'Hekr:Device(' + self.device_id + ')'

    def __repr__(self) -> str:
        """
        Generates debug string representation of the device
        :return: String representation (python-like)
        """
        return '<{} [device_id={}, protocol={}, direct_connector={}, cloud_connector={}]>'.format(
            self.__class__.__name__,
            self.device_id,
            self.protocol,
            self._direct_connector,
            self._cloud_connector
        )

    def __hash__(self) -> int:
        """
        Generate hash of the device (primarily for sets).
        :return: Hash of the device ID
        """
        return hash(self.device_id)

    # connector management
    @property
    def direct_connector(self) -> Optional['BaseDirectConnector']:
        return self._direct_connector

    @direct_connector.setter
    def direct_connector(self, value: Optional['BaseDirectConnector']):
        if not isinstance(value, BaseDirectConnector):
            raise ValueError("connector '%s' does not inherit from '%s'" % (value, BaseDirectConnector.__name__))
        value.attach_device(self, set_device_connector=False)
        self._direct_connector = value

    @property
    def cloud_connector(self) -> Optional['BaseCloudConnector']:
        return self._cloud_connector

    @cloud_connector.setter
    def cloud_connector(self, value: Optional['BaseCloudConnector']):
        if value is None:
            if self._cloud_connector is not None:
                self._cloud_connector.detach_device(self, unset_device_connector=False)
        if not isinstance(value, BaseCloudConnector):
            raise ValueError("connector '%s' does not inherit from '%s'" % (value, BaseCloudConnector.__name__))
        value.attach_device(self, set_device_connector=False)
        self._cloud_connector = value

    # protocol management
    @property
    def protocol(self) -> Optional[Type['Protocol']]:
        """Device protocol getter"""
        return self._protocol

    @protocol.setter
    def protocol(self, value: Type['Protocol']) -> None:
        """Device protocol setter"""
        for conn_type, current, from_protocol in [
            ('local', self._direct_connector, value.default_direct_connector_class),
            ('cloud', self._cloud_connector, value.default_cloud_connector_class),
        ]:
            if not (current is None or isinstance(current, from_protocol)):
                _LOGGER.warning(
                    'Existing %s connector class (%s) on device %s is not equal to, or not inherited from '
                    'the default %s connector class (%s) from protocol (%s). This may cause communication '
                    'issues.' % (conn_type, current.__class__, self, conn_type, from_protocol, value)
                )
        self._protocol = value

    def detect_device_protocol(self,
                               protocols: Iterable[Type['Protocol']],
                               set_protocol: bool = True) -> Optional[Type['Protocol']]:
        """
        Check whether device is compatible with any protocol within the list, and return the protocol if true.
        :param protocols: Iterable object of protocols (classes)
        :param set_protocol: (optional) Set protocol to device upon detection (default: true)
        :return: Protocol class, if found
        """
        d_i = self._device_info
        for p in protocols:
            if p.is_device_compatible(self) or d_i is not None and p.is_device_info_compatible(d_i):
                if set_protocol:
                    self.protocol = p
                return p
            _LOGGER.debug("Device %s incompatible with protocol %s" % (self, p))
        return None

    # built-in properties
    @property
    def device_type(self) -> DeviceType:
        """Return the device type for the device"""
        if self._device_info is None:
            return DeviceType.INDEPENDENT
        return self._device_info.device_type

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
    def control_key(self, value: str) -> None:
        """
        Control key setter.
        :param value:
        :return:
        """
        self._control_key = value

    # callback management
    @property
    def callbacks(self) -> Mapping[Optional[CommandID], List[ResponseCallback]]:
        """
        Return view on device's callbacks
        :return: View[Command ID => Callback list]
        """
        return MappingProxyType(self._callbacks)

    async def run_callbacks(self, response: 'Response', executor: Any = None) -> None:
        """
        Run callbacks bound to device.
        :param executor: (optional) Run synchronous callbacks in specified executor
        :param response: Response object
        """
        # Coroutine-related variables
        callback_coroutines = []

        # Collect sections for callbacks
        handle_sections = [None]
        if isinstance(response.decoded, tuple):
            handle_sections.append(response.decoded[0].command_id)

        # Handle all-callback coroutines
        for section in handle_sections:
            if section in self._callbacks and self._callbacks[section]:
                for callback in self._callbacks[section]:
                    callback_coroutines.append(create_callback_task(
                        callback, self, response,
                        executor=executor,
                        logger=_LOGGER,
                        suppress_exceptions=True,
                    ))

        if callback_coroutines:
            await asyncio.wait(callback_coroutines, return_when=asyncio.ALL_COMPLETED)

    def _get_callback_category(self, command: Optional[AnyCommand] = None):
        if command is None or isinstance(command, int):
            return command
        if isinstance(command, Command):
            return command.command_id
        if self.protocol is None:
            raise DeviceProtocolNotSetException(self)

        return self.protocol[command].command_id

    def callback_add(self, callback: ResponseCallback, command: Optional[AnyCommand] = None) -> Callable[[], None]:
        """
        Add callback to device communication flow.

        The signature of every callback must match the one of `Device._run_callbacks` method.

        :param callback: Callback (coroutine) function
        :param command: (optional) Command to attach callback to
        :return: Caller for removing added callback from callbacks
        """
        command_id = self._get_callback_category(command)
        callbacks = self._callbacks.setdefault(command_id, [])

        if callback not in callbacks:
            callbacks.append(callback)

        return partial(self.callback_remove, callback, command_id)

    def callback_remove(self, callback: ResponseCallback, command: Optional[AnyCommand] = None) -> None:
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

    # request management
    async def make_request(self,
                           action: Action,
                           params: dict = None,
                           message_id: Optional[MessageID] = None,
                           with_read: bool = False) -> Union[MessageID, 'Response']:
        """
        Make request to device.

        :param action: Action name.
        :param params: Request parameters.
        :param message_id: Message ID.
        :param with_read:
        :return: Message ID
        """
        connectors = [self._direct_connector, self._cloud_connector]

        if not any(connectors):
            raise DeviceConnectorsMissingException(self)

        for connector in connectors:
            if connector is not None and connector.is_connected:
                return await connector.make_request(action, params, message_id, with_read, self)

        raise DeviceConnectorsNotConnectedException(self)

    async def heartbeat(self) -> int:
        """Send heartbeat message

        Keyword Arguments:
            connection_type {DeviceConnectionType} -- Connection type to use (default: {None})

        Raises:
            HeartbeatFailedException: Heartbeat message sending failed
        """
        return await self.make_request(ACTION_HEARTBEAT_REQUEST)

    async def get_direct_response(self, message_id: Optional[MessageID] = None) -> 'Response':
        if self._direct_connector is None:
            raise DeviceConnectorMissingException(self, 'direct')

        return await self._direct_connector.get_response(message_id=message_id)

    async def get_cloud_response(self, message_id: Optional[MessageID] = None) -> 'Response':
        """
        Read cloud response from device and process.
        :param message_id:
        :return:
        """
        cloud_connector = self._cloud_connector
        if cloud_connector is None:
            raise DeviceConnectorMissingException(self, 'cloud')

        return await self._cloud_connector.get_response(message_id=message_id)

    # shorthand request commands
    async def command(self,
                      command: AnyCommand,
                      arguments: CommandData = None,
                      frame_number: int = None,
                      with_read: bool = False) -> Union[MessageID, 'Response']:
        """
        Execute device command.
        :param command: Command ID/name/object
        :param arguments: (optional) Data values for datagram
        :param frame_number: (optional) Frame number
        :param with_read: (optional; default to false) Whether to read response immediately after executing
        :return: Message ID
        """
        connectors = [self._direct_connector, self._cloud_connector]

        if not any(connectors):
            raise DeviceConnectorsMissingException(self)

        for connector in connectors:
            if connector is not None and connector.is_connected:
                if isinstance(connector, BaseCloudConnector):
                    data = self.protocol.encode_cloud(command, data=arguments, frame_number=frame_number)
                else:
                    data = self.protocol.encode_direct(command, data=arguments, frame_number=frame_number)

                return await connector.make_request(
                    ACTION_COMMAND_REQUEST,
                    params={"data": data},
                    with_read=with_read,
                    hekr_device=self
                )

        raise DeviceConnectorsNotConnectedException(self)

    # device info-related accessors
    @property
    def device_info(self) -> Optional[DeviceInfo]:
        """
        Accessor to get device info and raise exception if it is not set.
        :return: Device info, if set
        """
        return self._device_info

    @device_info.setter
    def device_info(self, new_info: DeviceInfo, update_control_key: bool = True) -> None:
        """
        Update device info with provided values
        :param new_info: Device info
        :param update_control_key: Allow control key update (default: true)
        """
        if update_control_key:
            control_key = new_info.control_key
            if control_key is not None:
                self.control_key = new_info.control_key

        self._device_info = new_info