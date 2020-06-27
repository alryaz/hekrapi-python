# -*- coding: utf-8 -*-
"""Device class module for Hekr API"""
__all__ = [
    'Device',
    'DeviceInfo',
    'DeviceType'
]
import asyncio
import logging
from enum import Enum
from functools import partial
from types import MappingProxyType
from typing import Optional, Any, TYPE_CHECKING, Dict, Callable, List, Union, Iterable, \
    Mapping, Type, Tuple

from .connector import LocalConnector, CloudConnector
from .const import ACTION_HEARTBEAT_REQUEST, ACTION_COMMAND_REQUEST
from .enums import DeviceType, WorkMode
from .exceptions import DeviceProtocolNotSetException, DeviceLocalConnectorBoundException, \
    DeviceCloudConnectorBoundException, DeviceConnectorsMissingException, DeviceConnectorsNotConnectedException, \
    DeviceConnectorNotConnectedException, ConnectorUnexpectedMessageIDException, \
    DeviceConnectorMissingException
from .helpers import sensitive_info_filter
from .protocol import Protocol
from .types import MessageID, Action, ResponseCallback, \
    AnyCommand, CommandData, DeviceID, CommandID

try:
    from typing import NoReturn
except ImportError:
    NoReturn = None

if TYPE_CHECKING:
    from .protocol import Command
    from .connector import _BaseConnector, Response

_LOGGER = logging.getLogger(__name__)


class DeviceInfo:
    class DeviceInfoProperty(property):
        pass

    def __init__(self, device_info_source: Mapping[str, Any], check_source: bool = True):
        self._device_info_source = device_info_source
        if check_source:
            self.check_device_info_dict(device_info_source, raise_for_error=True)

    def __str__(self):
        return '{}({})'.format(
            self.__class__.__name__,
            self.device_id,
        )

    def __repr__(self):
        return '<Hekr:{}[device_id={}, device_type={}, lan_address={}, wan_address={}]>'.format(
            self.__class__.__name__,
            self.device_id,
            self.device_type.name,
            self.lan_address,
            self.wan_address,
        )

    @classmethod
    def check_device_info_dict(cls,
                               device_info_dict: Mapping[str, Any],
                               raise_for_error: bool = False) -> List[Tuple[str, str]]:
        temp_object = cls(device_info_dict, check_source=False)
        invalid_properties = []

        for attribute, obj in cls.__dict__.items():
            if isinstance(obj, cls.DeviceInfoProperty):
                try:
                    obj.fget(temp_object)
                except (KeyError, IndexError) as e:
                    invalid_properties.append((attribute, e.args[0]))

        if raise_for_error and invalid_properties:
            raise ValueError('incomplete device info dictionary (missing keys: %s)'
                             % (', '.join(map(lambda x: x[1], invalid_properties))))
        return invalid_properties

    @property
    def device_info_source(self) -> Mapping[str, Any]:
        device_info_source = self._device_info_source
        return device_info_source if isinstance(device_info_source, MappingProxyType) \
            else MappingProxyType(device_info_source)

    @DeviceInfoProperty
    def device_type(self) -> DeviceType:
        return DeviceType(self._device_info_source['devType'])

    @DeviceInfoProperty
    def work_mode(self) -> WorkMode:
        return WorkMode(self._device_info_source['workModeType'])

    @DeviceInfoProperty
    def device_id(self) -> str:
        return self._device_info_source['devTid']

    @DeviceInfoProperty
    def product_id(self) -> str:
        return self._device_info_source['mid']

    @DeviceInfoProperty
    def control_key(self) -> str:
        return self._device_info_source['ctrlKey']

    @DeviceInfoProperty
    def product_name(self) -> str:
        return self._device_info_source['productName']['en_US']

    @DeviceInfoProperty
    def category_name(self) -> str:
        return self._device_info_source['categoryName']['en_US']

    @DeviceInfoProperty
    def sdk_version(self) -> str:
        return self._device_info_source['sdkVer']

    @DeviceInfoProperty
    def firmware_version(self) -> str:
        return self._device_info_source['binVersion']

    @DeviceInfoProperty
    def url_logo(self) -> str:
        return self._device_info_source['logo']

    @DeviceInfoProperty
    def mac_address(self) -> str:
        return self._device_info_source['mac']

    @DeviceInfoProperty
    def lan_address(self) -> str:
        return self._device_info_source['lanIp']

    @DeviceInfoProperty
    def wan_address(self) -> Optional[str]:
        return self._device_info_source['gis'].get('ip', {}).get('ip')

    @DeviceInfoProperty
    def is_online(self) -> bool:
        return self._device_info_source['online']

    @DeviceInfoProperty
    def rssi(self) -> Optional[int]:
        return self._device_info_source.get('rssi')

    @DeviceInfoProperty
    def bind_key(self) -> str:
        return self._device_info_source['bindKey']

    @DeviceInfoProperty
    def device_name(self):
        return self._device_info_source['deviceName']

    @DeviceInfoProperty
    def name(self):
        return self._device_info_source['name']

    @DeviceInfoProperty
    def cloud_connect_host(self):
        return self._device_info_source['dcInfo']['connectHost']


class Device:
    """Device class for Hekr API"""

    def __init__(self,
                 device_id: Union[DeviceID, DeviceInfo],
                 control_key: Optional[str] = None,
                 protocol: Optional[Union[Type['Protocol'], Iterable[Type['Protocol']]]] = None,
                 device_info: Optional[DeviceInfo] = None,
                 local_connector: Optional['LocalConnector'] = None,
                 cloud_connector: Optional['CloudConnector'] = None,
                 automatic_authentication: bool = True):
        # generic attributes
        if isinstance(device_id, DeviceInfo):
            if not (device_info is None or device_info == device_id):
                raise ValueError('differing device info provided for first device_id argument and device_info argument')
            device_info = device_id
            device_id = device_info.device_id

        self._device_id: DeviceID = device_id
        self._control_key: Optional[str] = control_key
        self._device_info: Optional[DeviceInfo] = device_info
        self._local_connector: Optional[LocalConnector] = local_connector
        self._cloud_connector: Optional['CloudConnector'] = cloud_connector
        self._callbacks: Dict[Optional[int], List[ResponseCallback]] = dict()
        self._last_frame_number = 0

        self.automatic_authentication = automatic_authentication

        if device_info:
            self.device_info = device_info

        if not (protocol is None or issubclass(protocol, Protocol)):
            protocol = self.detect_device_protocol(protocol, set_protocol=False)
            if protocol is None:
                raise ValueError('device could not detect protocol from provided set of protocols')

        self._protocol: Optional[Type['Protocol']] = protocol

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
        return '<{} [device_id={}, protocol={}, local_connector={}, cloud_connector={}]>'.format(
            self.__class__.__name__,
            self.device_id,
            self.protocol,
            self._local_connector,
            self._cloud_connector
        )

    def __hash__(self) -> int:
        """
        Generate hash of the device (primarily for sets).
        :return: Hash of the device ID
        """
        return hash(self.device_id)

    # protocol management
    @property
    def protocol(self) -> Optional[Type['Protocol']]:
        """Device protocol getter"""
        return self._protocol

    @protocol.setter
    def protocol(self, value: Type['Protocol']) -> NoReturn:
        """Device protocol setter"""
        for conn_type, current, from_protocol in [
            ('local', self._local_connector, value.default_local_connector_class),
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
        for protocol in protocols:
            if protocol.is_device_compatible(self):
                if set_protocol:
                    self.protocol = protocol
                return protocol
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
    def control_key(self, value: str) -> NoReturn:
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

    async def run_callbacks(self, response: 'Response') -> NoReturn:
        """
        Run callbacks bound to device.
        :param response: Response object
        """
        # Coroutine-related variables
        callback_coroutines = []
        loop: Optional[asyncio.AbstractEventLoop] = None

        # Collect sections for callbacks
        handle_sections = [None]
        if isinstance(response.decoded, tuple):
            handle_sections.append(response.decoded[0].command_id)

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
        if command is None or isinstance(command, int):
            return command
        if isinstance(command, Command):
            return command.command_id
        if self.protocol is None:
            raise DeviceProtocolNotSetException(self)

        return self.protocol[command].command_id

    def callback_add(self, callback: ResponseCallback, command: Optional[AnyCommand] = None) -> Callable[[], NoReturn]:
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

    def callback_remove(self, callback: ResponseCallback, command: Optional[AnyCommand] = None) -> NoReturn:
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

    # connector management
    def _attach_connector(self, conn_type: str, value: '_BaseConnector') -> NoReturn:
        target_attr = '_%s_connector' % conn_type
        current_connector = getattr(self, target_attr, None)
        if not (current_connector is None or current_connector == value):
            raise ValueError(conn_type + ' connector already exists on device')

        if value is not None:
            protocol = self.protocol
            if protocol is not None:
                protocol_class = protocol.default_local_connector_class
                if not isinstance(value, protocol_class):
                    _LOGGER.warning(
                        'New %s protocol class (%s) is not equal to, or not inherited from the default '
                        '%s connector class (%s) from device (%s) protocol (%s). This may cause communication '
                        'issues.' % (conn_type, value.__class__, conn_type, protocol_class, self, protocol)
                    )
            value.attach_device(self)

        setattr(self, target_attr, value)

    @property
    def local_connector(self) -> Optional['LocalConnector']:
        """Local connector getter"""
        return self._local_connector

    @local_connector.setter
    def local_connector(self, value: 'LocalConnector') -> NoReturn:
        """Local connector setter"""
        self._attach_connector('local', value)

    @property
    def cloud_connector(self) -> Optional['CloudConnector']:
        """Cloud connector accessor"""
        return self._cloud_connector

    @cloud_connector.setter
    def cloud_connector(self, value: 'CloudConnector') -> NoReturn:
        """Cloud connector setter"""
        self._attach_connector('cloud', value)

    def create_local_connector(self, *args, connector_class: Optional[Type['LocalConnector']] = None, **kwargs):
        if self._local_connector is not None:
            raise DeviceLocalConnectorBoundException(self, self._local_connector)

        local_connector = (
            LocalConnector(*args, **kwargs) if self.protocol is None
            else self.protocol.create_local_connector(*args, **kwargs)
        ) if connector_class is None else connector_class(*args, **kwargs)

        local_connector.attach_device(self)
        self._local_connector = local_connector
        return local_connector

    def create_cloud_connector(self, *args, connector_class: Optional[Type['CloudConnector']] = None, **kwargs):
        if self._cloud_connector:
            raise DeviceCloudConnectorBoundException(self, self._cloud_connector)

        cloud_connector = (
            CloudConnector(*args, **kwargs) if self.protocol is None
            else self.protocol.create_cloud_connector(*args, **kwargs)
        ) if connector_class is None else connector_class(*args, **kwargs)

        cloud_connector.attach_device(self)
        self._cloud_connector = cloud_connector
        return cloud_connector

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
        connectors = [self._local_connector, self._cloud_connector]

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

    async def get_local_response(self, message_id: Optional[MessageID] = None) -> 'Response':
        local_connector = self._local_connector
        if local_connector is None:
            raise DeviceConnectorMissingException(self, 'local')

        return await self._local_connector.get_response(message_id=message_id)

    async def get_cloud_response(self, message_id: Optional[MessageID] = None) -> 'Response':
        """
        Read cloud response from device and process.
        :param message_id:
        :return:
        """
        cloud_connector = self._cloud_connector
        if cloud_connector is None:
            raise DeviceConnectorMissingException(self, 'cloud')

        return await self._get_response(cloud_connector, message_id=message_id)

    # shorthand request commands
    async def command(self,
                      command: AnyCommand,
                      data: CommandData = None,
                      frame_number: int = None,
                      with_read: bool = False) -> Union[MessageID, 'Response']:
        """
        Execute device command.
        :param command: Command ID/name/object
        :param data: (optional) Data values for datagram
        :param frame_number: (optional) Frame number
        :param with_read: (optional; default to false) Whether to read response immediately after executing
        :return: Message ID
        """
        connectors = [self._local_connector, self._cloud_connector]

        if not any(connectors):
            raise DeviceConnectorsMissingException(self)

        for connector in connectors:
            if connector is not None and connector.is_connected:
                encoder = self.protocol.encode_cloud if isinstance(connector, CloudConnector) \
                    else self.protocol.encode_local
                return await connector.make_request(
                    ACTION_COMMAND_REQUEST,
                    params={
                        "data": encoder(command, data=data, frame_number=frame_number)
                    },
                    with_read=with_read,
                    hekr_device=self
                )

        raise DeviceConnectorsNotConnectedException(self)

        return await self.make_request(ACTION_COMMAND_REQUEST, {"data": encoded_data}, with_read=with_read)

    # device info-related accessors
    @property
    def device_info(self) -> Optional[DeviceInfo]:
        """
        Accessor to get device info and raise exception if it is not set.
        :return: Device info, if set
        """
        return self._device_info

    @device_info.setter
    def device_info(self, new_info: DeviceInfo, update_control_key: bool = True) -> NoReturn:
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
