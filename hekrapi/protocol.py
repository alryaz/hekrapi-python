# -*- coding: utf-8 -*-
# pylint: disable=too-many-arguments
"""Protocol class module for Hekr API"""
__all__ = [
    'Protocol',
    'Argument',
    'Command',
    'Encoding',
    'TO_FLOAT',
    'TO_BOOL',
    'TO_STR',
    'TO_SIGNED_FLOAT',
    'signed_float_converter',
    'load_all_supported_protocols',
    'register_supported_protocol'
]

import logging
import re
from enum import IntEnum
from functools import partial
from json import loads as json_loads
from typing import TYPE_CHECKING, Union, List, Dict, Optional, Callable, Any, Tuple, NoReturn, Type, Iterable

from .connector import LocalConnector, CloudConnector
from .const import FRAME_START_IDENTIFICATION
from .enums import Encoding, FrameType, WorkMode
from .exceptions import CommandDataMissingException, CommandDataLessThanException, CommandDataGreaterThanException, \
    CommandDataExtraException, CommandDataInvalidPrefixException, CommandDataInvalidLengthException, \
    CommandDataInvalidChecksumException, CommandDataUnknownCommandException, CommandDataInvalidFrameTypeException, \
    HekrAPIException
from .types import CommandData, MessageEncoded, MessageData, RawDataType, JSONDataType, CommandID, AnyCommand

if TYPE_CHECKING:
    from .device import Device, DeviceInfo

_LOGGER = logging.getLogger(__name__)

REGISTERED_PROTOCOLS: Dict[str, '_ProtocolMeta'] = dict()


# regex borrowed from https://stackoverflow.com/a/12867228
PROTOCOL_ID_REGEX = re.compile(r'((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))')


def register_supported_protocol(protocol_id: Union[str, Type['Protocol']],
                                protocol_class: Optional[Type['Protocol']] = None):
    if protocol_class is None:
        if issubclass(protocol_id, Protocol):
            name = protocol_id.__name__
            if name.lower().endswith('protocol'):
                name = name[:-8]
            if not name:
                raise RuntimeError('could not generate identifier for protocol')

            register_protocol_id = PROTOCOL_ID_REGEX.sub(r'_\1', name).lower()
            return register_supported_protocol(register_protocol_id, protocol_id)

        elif isinstance(protocol_id, str):
            return partial(register_supported_protocol, protocol_id)

        raise TypeError('protocol registration allowed only with subclasses of hekrapi.protocol.Protocol')

    if protocol_class == Protocol:
        raise ValueError('cannot register base protocol class')

    if protocol_id in REGISTERED_PROTOCOLS:
        raise RuntimeError('attempting to register protocol "%s" multiple times (old class: %s, new class: %s)'
                           % (protocol_id, REGISTERED_PROTOCOLS[protocol_id], protocol_class))

    REGISTERED_PROTOCOLS[protocol_id] = protocol_class
    return protocol_class


def load_all_supported_protocols():
    import pkgutil
    from os.path import dirname
    for _, module, _ in pkgutil.iter_modules([dirname(__file__) + '/protocols']):
        __import__('hekrapi.protocols.' + module, globals(), locals(), [''])

    return REGISTERED_PROTOCOLS


def signed_float_converter(threshold, type_input=int, type_output=float):
    """ Generates a signed float converter. """

    def convert_input(value):
        """ Adds negative value to threshold to restore original """
        value = type_input(value)
        return threshold - value if value < 0 else value

    def convert_output(value):
        """ Inverts sign if original is equal to or greater than threshold """
        value = type_output(value)
        return value if value < threshold else threshold - value

    return convert_input, convert_output


TO_FLOAT = (int, float)
TO_BOOL = (int, bool)
TO_STR = (int, str)
TO_SIGNED_FLOAT = signed_float_converter(1000000)


def remove_none(obj):
    """
    Remove empty values recursively from an iterable dictionary.

    :param obj:
    :return:
    """
    if isinstance(obj, (list, tuple, set)):
        return type(obj)(remove_none(x) for x in obj if x is not None)

    elif isinstance(obj, dict):
        return dict([
            (remove_none(k), remove_none(v))
            for k, v in obj.items() if k is not None and v is not None
        ])

    return obj


ArgumentType = Callable[[Any], Any]


class Argument:
    """Argument class for HekrAPI"""

    def __init__(self,
                 name: str,
                 value_type: Union[Tuple[ArgumentType, ArgumentType], ArgumentType] = str,
                 length: Optional[int] = None,
                 variable: Optional[str] = None,
                 multiplier: Optional[Union[int, float]] = None,
                 decimals: Optional[int] = None,
                 value_min: Optional[Union[int, float]] = None,
                 value_max: Optional[Union[int, float]] = None,
                 value_default: Optional[Any] = None,
                 description: Optional[str] = None):
        """
        Argument class constructor.
        :param name: Argument name
        :param value_type: Input and output type (may be different if defined as tuple) (default: str)
        :param length: Length of input value (default: unlimited)
        :param variable: Variable name (default: argument's name)
        :param multiplier: What to multiply input/divide output values by (default: not set)
        :param decimals: Decimals to round input value to (in absence of explicit setting, extracted from
                         provided `multiply` attribute) (default: not set)
        :param value_min: Minimum value during encoding (default: not set)
        :param value_max: Maximum value during encoding (default: not set)
        """
        self.name = name
        self.variable = variable
        self.length = length

        if isinstance(value_type, IntEnum):
            self.type_input = int
            self.type_output = value_type

        elif isinstance(value_type, tuple):
            self.type_input = value_type[0]
            self.type_output = value_type[1]

        else:
            self.type_input = value_type
            self.type_output = value_type

        self.value_min = value_min
        self.value_max = value_max
        self.value_default = value_default
        self.decimals = decimals
        self.multiplier = multiplier
        self.__doc__ = description

    def __repr__(self):
        """Overloaded argument definition

        Returns:
            str -- Human-friendly argument definition
        """
        return '<{}({})>'.format(self.__class__.__name__, self.name)

    def __eq__(self, other: 'Argument'):
        """
        Compare two argument objects.
        :param other:
        :return:
        """
        if not isinstance(other, Argument):
            return False

        return (self.name == other.name
                and self.variable == other.variable
                and self.length == other.length
                and self.type_input == other.type_input
                and self.type_output == other.type_output
                and self.value_min == other.value_min
                and self.value_max == other.value_max
                and self.value_default == other.value_default
                and self.decimals == other.decimals
                and self.multiplier == other.multiplier)

    @property
    def decimals(self) -> int:
        """Getter for decimals count to round result to

        Extracts decimal point from multiplier unless a specific value is set
        via getter method.

        Returns:
            int -- Floating point digits
        """
        if self._decimals is None:
            decimals = str(self.multiplier)[::-1].find('.')
            return 0 if decimals < 0 else decimals

        return self._decimals

    @decimals.setter
    def decimals(self, value):
        """Getter for decimals count to round result to"""
        self._decimals = value

    @property
    def variable(self) -> str:
        """Getter for variable name

        Variable name is used in several encoding/decoding scenarios.
        It defaults to `name` attribute if not set explicitly.

        Returns:
            str -- Variable name
        """
        if self._variable is None:
            return self.name
        return self._variable

    @variable.setter
    def variable(self, value):
        """Setter for variable name"""
        self._variable = value


class Command:
    """Base command class for HekrAPI"""

    _frame_type_collisions = {
        '_invoke_command_id': (FrameType.SEND,),
        '_response_command_id': (FrameType.RECEIVE,),
    }

    def __init__(self,
                 command_id: int,
                 frame_type: FrameType = FrameType.SEND,
                 arguments: Optional[Iterable[Argument]] = None,
                 response_command_id: Optional[int] = None,
                 invoke_command_id: Optional[int] = None,
                 description: Optional[str] = None):
        """
        Command class constructor.

        :param command_id: Command identifier for datagrams.
        :param frame_type: Frame type for command.
        :param arguments: List of arguments bound to command.
        :param response_command_id: Command ID to wait for response from.
        :param invoke_command_id: Command ID to expect invocation from.
        """
        self._command_id = command_id

        # circular checking prevents following private attributes
        # from being created automatically
        self._response_command_id = None
        self._invoke_command_id = None
        self._frame_type = None
        self._arguments = [] if arguments is None else list(arguments)

        self.frame_type = frame_type
        self.response_command_id = response_command_id
        self.invoke_command_id = invoke_command_id
        self.arguments = arguments
        self.__doc__ = description

    def __repr__(self) -> str:
        """
        Pythonize command object representation.

        :return: Command representation (Python-like)
        :rtype: str
        """
        return '<{} [command_id={}]>'.format(
            self.__class__.__name__,
            self.command_id
        )

    def __int__(self) -> int:
        """
        Command ID alternative getter.

        :return:
        """
        return self.command_id

    def __eq__(self, other: 'Command'):
        if not isinstance(other, Command):
            return False

        return (self._command_id == other._command_id
                and self._frame_type == other._frame_type
                and self._response_command_id == other._response_command_id
                and self._invoke_command_id == other._invoke_command_id
                and self._arguments == other._arguments)

    @property
    def command_id(self) -> int:
        """
        Command ID getter.

        :return: Command ID.
        :rtype: int
        """
        return self._command_id

    @property
    def arguments(self) -> List[Argument]:
        """
        Arguments list getter.
        :return: List of arguments.
        :rtype: list[Argument]
        """
        return self._arguments

    @arguments.setter
    def arguments(self, value: Optional[Iterable[Argument]]) -> NoReturn:
        """
        Arguments list setter (updater).
        """
        self._arguments.clear()
        if value:
            self._arguments.extend(value)

    @property
    def frame_type(self) -> FrameType:
        """
        Getter for `frame_type` attribute.

        :return: Frame type for command.
        :rtype: FrameType
        """
        return self._frame_type

    @frame_type.setter
    def frame_type(self, value: FrameType) -> None:
        """
        Setter for `frame_type` attribute.

        Coerces any incoming value on invocation to `FrameType` class instances.
        Throws exceptions when incorrect data is being fed.

        :param value: Frame type for command.
        :raises:
            ValueError: if frame type is SEND and response_command_id
        """
        if value is None:
            raise ValueError('frame type cannot be None')
        elif isinstance(value, str):
            new_frame_type = FrameType[value.upper()]
        elif not isinstance(value, FrameType):
            new_frame_type = FrameType(value)
        else:
            new_frame_type = value

        for collision_variable, frame_types in self._frame_type_collisions.items():
            if new_frame_type in frame_types and getattr(self, collision_variable) is not None:
                raise ValueError(f"{new_frame_type.name} not allowed with non-empty {collision_variable.strip('_')}")

        self._frame_type = new_frame_type

    @property
    def invoke_command_id(self) -> Optional[int]:
        """Invoke command ID getter"""
        return self._invoke_command_id

    @invoke_command_id.setter
    def invoke_command_id(self, value: Optional[int]) -> NoReturn:
        if value is not None:
            if self.frame_type in self._frame_type_collisions['_invoke_command_id']:
                raise ValueError(f"invoke_command_id not allowed with frame type {self.frame_type.name}")
        self._invoke_command_id = value

    @property
    def response_command_id(self) -> Optional[int]:
        """Response command ID getter"""
        return self._response_command_id

    @response_command_id.setter
    def response_command_id(self, value: int) -> NoReturn:
        if value is not None:
            if self.frame_type in self._frame_type_collisions['_response_command_id']:
                raise ValueError(f"response_command_id not allowed with frame type {self.frame_type.name}")
        self._response_command_id = value

    @staticmethod
    def _process_arguments(command: 'Command',
                           callback: Callable[[Union[str, Argument], Any], Any],
                           arguments: List[Argument],
                           data: Optional[CommandData] = None,
                           use_variable_names: bool = False,
                           filter_values: bool = True,
                           ignore_extra: bool = False,
                           pass_argument: bool = False) -> NoReturn:
        if data is None:
            data = dict()

        call_after = []
        argument_keys = set()
        missing_keys = set()

        for argument in arguments:
            key = argument.variable if use_variable_names else argument.name
            value_input = data.get(key, None)

            if value_input is None:
                if argument.value_default is None:
                    missing_keys.add(key)
                value_input = argument.value_default

            if missing_keys:
                continue

            argument_keys.add(key)

            if argument.value_min is not None and argument.value_min > value_input:
                raise CommandDataLessThanException(command, key, argument.value_min)

            if argument.value_max is not None and argument.value_max < value_input:
                raise CommandDataGreaterThanException(command, key, argument.value_max)

            if filter_values:
                if argument.multiplier:
                    value_input /= argument.multiplier

                value_input = argument.type_input(value_input)

            call_after.append(
                partial(
                    callback, argument if pass_argument else argument.variable,
                    value_input
                )
            )

        if missing_keys:
            raise CommandDataMissingException(command, missing_keys)

        if not ignore_extra:
            extra_keys = data.keys() - argument_keys
            if extra_keys:
                raise CommandDataExtraException(command, extra_keys)

        # Process callbacks after everything is OK
        for run_callback in call_after:
            run_callback()

    # Command encoding/decoding: Raw
    def encode_arguments_raw(self,
                             data: Optional[CommandData] = None,
                             use_variable_names: bool = False,
                             filter_values: bool = True) -> bytearray:
        """Encode arguments into an array of bytes."""
        result = bytearray()
        appender = partial(append_bytes_to_array, result)

        # noinspection PyTypeChecker
        Command._process_arguments(
            command=self,
            callback=appender,
            arguments=self.arguments,
            data=data,
            use_variable_names=use_variable_names,
            filter_values=filter_values,
            pass_argument=True
        )

        return result

    def decode_arguments_raw(self,
                             data: Union[bytes, bytearray],
                             use_variable_names: bool = False,
                             filter_values: bool = True,
                             ignore_extra: bool = False) -> CommandData:
        """Decode passed data"""
        decoded = data[5:-1]

        result = {}
        current_pos = 0
        data_length = len(decoded)
        for argument in self.arguments:
            key = argument.variable if use_variable_names else argument.name

            next_pos = current_pos + argument.length
            if next_pos > data_length:
                raise CommandDataMissingException(self, [key])

            value_output = int.from_bytes(decoded[current_pos:next_pos], byteorder='big', signed=False)

            # @TODO: decide on whether clamping/exceptions are required on invalid data

            if filter_values:
                value_output = argument.type_output(value_output)

                if argument.multiplier is not None:
                    value_output *= argument.multiplier
                    if argument.decimals is not None:
                        value_output = round(value_output, argument.decimals)

            result[key] = value_output
            current_pos = next_pos

        if not ignore_extra and current_pos < data_length:
            raise CommandDataExtraException(self, decoded[current_pos:])

        return result

    def encode_raw(self, data: Optional[CommandData] = None, frame_number: int = 1, use_variable_names: bool = False,
                   filter_values: bool = True, only_datagram: bool = False) -> Union[Dict[str, Any], str]:
        encoded_arguments = self.encode_arguments_raw(
            data=data,
            use_variable_names=use_variable_names,
            filter_values=filter_values
        )

        raw = bytearray()
        raw.append(FRAME_START_IDENTIFICATION)
        raw.append(self.frame_type.value)
        raw.append(frame_number % 256)
        raw.append(self.command_id)
        raw.extend(encoded_arguments)
        raw.insert(1, len(raw) + 2)
        raw.append(sum(raw) % 0x100)

        datagram = raw.hex().upper()

        if only_datagram:
            return datagram

        return {"raw": datagram}

    @staticmethod
    def convert_raw_data(data: Union[RawDataType, MessageData]) -> bytearray:
        if isinstance(data, dict):
            data = data.get('raw')
            if not data:
                raise ValueError('expected dictionary with non-empty raw key')

        if isinstance(data, bytearray):
            return data

        elif isinstance(data, str):
            return bytearray.fromhex(data)

        elif isinstance(data, bytes):
            return bytearray(data)

        raise TypeError('type "%s" does not match supported raw types (%s)'
                        % (type(data), (str, bytes, bytearray)))

    @staticmethod
    def get_command_id_from_raw(data: Union[RawDataType, MessageData], validate: bool = True) -> int:
        """
        Helper method to retrieve command ID from raw datagram.
        :param data:
        :param validate:
        :return: int - Command ID
        """
        decoded = data if isinstance(data, bytearray) \
            else Command.convert_raw_data(data)

        if validate:
            # Common prefix is located at first byte
            if decoded[0] != FRAME_START_IDENTIFICATION:
                raise CommandDataInvalidPrefixException(decoded)

            # Frame length is located at second byte
            frame_length = decoded[1]
            if frame_length != len(decoded):
                raise CommandDataInvalidLengthException(decoded)

            # Checksum is located at last byte
            checksum = decoded[-1]
            current_checksum = sum(decoded[:-1]) % 0x100
            if checksum != current_checksum:
                raise CommandDataInvalidChecksumException(decoded)

        # Command ID is located at 5th byte
        return decoded[4]

    # Command encoding/decoding: JSON
    def encode_arguments_json(self, data: CommandData, use_variable_names: bool = False, filter_values: bool = True,
                              ignore_extra: bool = False) -> Dict[str, Any]:
        result = dict()
        Command._process_arguments(
            command=self,
            callback=result.__setitem__,
            arguments=self.arguments,
            data=data,
            use_variable_names=use_variable_names,
            filter_values=filter_values,
            pass_argument=False,
            ignore_extra=ignore_extra
        )

        return result

    def decode_arguments_json(self,
                              data: Dict[str, Any],
                              use_variable_names: bool = False,
                              filter_values: bool = True,
                              use_defaults: bool = False) -> CommandData:
        """Decode passed data"""
        result = {}
        # @TODO: cmdId validation required?
        for argument in self.arguments:
            key = argument.variable if use_variable_names else argument.name

            if argument.variable not in data:
                if use_defaults and argument.value_default is not None:
                    result[key] = argument.value_default
                    continue
                raise CommandDataMissingException(self, [key])

            value_output = data[argument.variable]

            if filter_values:
                value_output = argument.type_output(value_output)

                if argument.multiplier is not None:
                    value_output *= argument.multiplier
                    if argument.decimals is not None:
                        value_output = round(value_output, argument.decimals)

            result[key] = value_output

        return result

    def encode_json(self, data: Optional[CommandData] = None, use_variable_names: bool = False,
                    filter_values: bool = True) -> MessageEncoded:
        encoded_arguments = self.encode_arguments_json(
            data=data,
            use_variable_names=use_variable_names,
            filter_values=filter_values
        )
        encoded_arguments["cmdId"] = self.command_id

        return encoded_arguments

    @staticmethod
    def convert_json_data(data: Union[str, MessageData]) -> JSONDataType:
        if isinstance(data, str):
            return json_loads(data)

        elif isinstance(data, dict):
            return data

        raise ValueError('expected JSON string or dict')

    @staticmethod
    def get_command_id_from_json(data: Union[str, MessageData],
                                 validate: bool = True) -> int:
        decoded = data if isinstance(data, dict) else Command.convert_json_data(data)

        command_id = decoded.get('cmdId')
        if command_id is None:
            if 'raw' in decoded:
                return Command.get_command_id_from_raw(data, validate=validate)
            raise CommandDataUnknownCommandException(['cmdId'])

        # @TODO: json validation?

        return command_id


def append_bytes_to_array(byte_result: bytearray, argument: Argument, value: int):
    byte_result += value.to_bytes(
        argument.length,
        byteorder='big',
        signed=False
    )


class _ProtocolMeta(type):
    """
    Metaclass for protocol base.
    """
    # Name pre-generation regular expression
    _name_conversion_regex = re.compile(r'((?<=[a-z])[A-Z]|(?<!\A)[A-Z](?=[a-z]))')
    _commands_by_id = None
    _commands_by_name = None

    @staticmethod
    def _get_commands_by_name(source_dict: Dict[str, Any]) -> Dict[str, Command]:
        """
        Filter source dictionary to include commands indexed by name.
        :param source_dict: Source dictionary
        :return: Dictionary of commands indexed by attached names
        """
        # @TODO: support partials
        return {
            name: value
            for name, value in source_dict.items()
            if isinstance(value, Command)
        }

    @staticmethod
    def _get_commands_by_id(source_dict: Dict[str, Any]) -> Dict[int, Command]:
        """
        Filter source dictionary to include commands indexed by command ID
        :param source_dict: Source dictionary
        :return: Dictionary of commands indexed by their IDs
        """
        return {
            value.command_id: value
            for value in source_dict.values()
            if isinstance(value, Command)
        }

    @property
    def commands_by_id(cls) -> Dict[CommandID, Command]:
        """
        Commands by ID getter.
        :return: Dictionary of commands indexed by their IDs
        """
        return cls._commands_by_id

    @property
    def commands_by_name(cls) -> Dict[str, Command]:
        """
        Commands by name getter.
        :return: Dictionary of commands indexed by attached names
        """
        return cls._commands_by_name

    def _recursive_dict(cls, __base_class: Optional[Type[type]] = None) -> Dict[str, Any]:
        base_class = _ProtocolMeta if __base_class is None else __base_class
        total_dict = dict()
        for base in cls.__bases__:
            if isinstance(base, base_class):
                recursive_dict_call = getattr(base, '_recursive_dict', None)
                recursive_dict = base.__dict__ if recursive_dict_call is None \
                    else recursive_dict_call(base_class)
                total_dict.update(recursive_dict)
        total_dict.update(cls.__dict__)
        return total_dict

    def __new__(mcs, name, bases, attributes: Dict[str, Any]):
        if attributes.get('protocol_name') is None:
            protocol_name = name[:-8] if name.lower().endswith('protocol') else name
            protocol_name = mcs._name_conversion_regex.sub(r' \1', protocol_name)

            attributes['protocol_name'] = protocol_name

        local_commands: Dict[str, Command] = dict()
        for key, value in attributes.items():
            if isinstance(value, Command):
                local_commands[key] = value

        commands_by_name = dict()
        for base in bases:
            if hasattr(base, '_commands_by_name'):
                commands_by_name.update(getattr(base, '_commands_by_name'))
        commands_by_name.update(local_commands)

        commands_id_collisions: Dict[CommandID, List[Tuple[name, Command]]] = dict()
        for key, command in commands_by_name.items():
            command_id = command.command_id
            commands_id_collisions.setdefault(command_id, []).append((key, command))

        commands_by_id: Dict[CommandID, Command] = dict()
        for command_id, commands_list in commands_id_collisions.items():
            last_pair = commands_list[-1]
            if len(commands_list) > 1:
                print("Duplicate command ID '%d' for protocol %s detected. Encoding/decoding operations"
                      "for method(s) %s will be handled by '%s'"
                      % (command_id, name, ', '.join(map("'{0[0]}'".format, commands_list)), last_pair[0]))
            commands_by_id[command_id] = last_pair[1]

        attributes['_commands_by_name'] = commands_by_name
        attributes['_commands_by_id'] = commands_by_id

        return type.__new__(mcs, name, bases, attributes)

    def __getitem__(cls, item: Union[str, int]):
        if isinstance(item, str):
            value = cls.commands_by_name.get(item)
            if value is None:
                raise IndexError('command "%s" not found in protocol' % item)

        else:
            value = cls.commands_by_id.get(item)
            if value is None:
                raise IndexError('command ID "%d" not found in protocol' % item)

        return value

    def __setitem__(cls, key: str, value: Command):
        raise AttributeError('modifying commands is only allowed through inheritance')

    def __setattr__(self, key: str, value: Union[Command, Any]) -> NoReturn:
        raise AttributeError('modifying attributes is only allowed through inheritance')

    def encode(cls, command: Union[int, str], data: Optional[CommandData] = None, *args, **kwargs) -> MessageData:
        """
        Encode message using given arguments.
        :param command: Command ID / Name (must exist within the protocol)
        :param data: Input dictionary of data to encode
        :param args: Additional positional arguments to the encoder
        :param kwargs: Additional keyword arguments to the encoder
        :return: Dictionary with message parameters
        """
        raise NotImplementedError

    def decode(cls, data: MessageData, *args, **kwargs) -> Tuple[Command, Dict[str, Any], Optional[int]]:
        """
        Decode message using given arguments.
        :param data: Input data
        :param args: Additional positional arguments to the decoder
        :param kwargs: Additional keyword arguments to the decoder
        :return: Dictionary of data decoded from response
        """
        raise NotImplementedError


class Protocol(metaclass=_ProtocolMeta):
    """Base protocol for other protocols to subclass"""
    # Protocol name (will be auto-generated upon class initialization)
    protocol_name: Optional[str] = None

    # Default local encoding type
    default_local_encoding_type: Encoding = NotImplemented

    # Default cloud encoding type
    default_cloud_encoding_type: Encoding = NotImplemented

    # Default local port for local connections
    default_local_port: int = NotImplemented

    # Use said local connector class when instantiating connections
    default_local_connector_class: Type[LocalConnector] = LocalConnector

    # Use said cloud connector class when instantiating connections
    default_cloud_connector_class: Type[CloudConnector] = CloudConnector

    @staticmethod
    def _device_compatibility_checker(device: 'Device') -> bool:
        """
        Optional device compatibility checker (used in auto-detection)
        :param device: Device
        :return: Whether device is compatible
        """
        return NotImplemented

    @staticmethod
    def _device_info_compatibility_checker(device_info: 'DeviceInfo') -> bool:
        """
        Optional device info compatibility checker (used in auto-detection)
        :param device_info: Device info
        :return: Whether device info is compatible
        """
        return NotImplemented

    @classmethod
    def is_device_compatible(cls, device: 'Device') -> bool:
        """
        Check whether passed device is compatible with given protocol.
        :param device: Device to check compatibility against
        :return: Compatibility result
        """
        try:
            result = cls._device_compatibility_checker(device)
            if result is NotImplemented and device.device_info is not None:
                return cls._device_info_compatibility_checker(device.device_info)

        except (AttributeError, ValueError, IndexError, KeyError, HekrAPIException):
            _LOGGER.exception('Exception raised while checking device info for compatibility')
            return False
        return False

    @classmethod
    def is_device_info_compatible(cls, device_info: 'DeviceInfo'):
        if cls._device_info_compatibility_checker:
            try:
                return cls._device_info_compatibility_checker(device_info)

            except (AttributeError, ValueError, IndexError, KeyError, HekrAPIException):
                _LOGGER.exception('Exception raised while checking device info for compatibility')
                return False

        return False

    @classmethod
    def create_local_connector(cls, host: str, port: Optional[int] = None, **kwargs):
        if port is None:
            port = cls.default_local_port
        return cls.default_local_connector_class(host, port=port, **kwargs)

    @classmethod
    def create_cloud_connector(cls, *args, **kwargs):
        return cls.default_cloud_connector_class(*args, **kwargs)

    @classmethod
    def encode(cls,
               encoding: Union[Encoding, WorkMode],
               command: AnyCommand,
               data: Optional[CommandData] = None,
               use_variable_names: bool = False,
               filter_values: bool = True,
               frame_number: Optional[int] = None) -> MessageData:
        """
        Encode message using given arguments.
        :param encoding:
        :param command: Command ID / Name (must exist within the protocol)
        :param data: Input dictionary of data to encode
        :param use_variable_names: Use variable names when processing input dictionary
        :param filter_values: Convert input values to those accepted by device using command filters
        :param frame_number: (for raw encoding) Frame number to append to message
        :return: Dictionary with message parameters
        """
        command = cls[command] if isinstance(command, (int, str)) else command

        if frame_number is None:
            frame_number = 1

        encoded_data = dict()
        if encoding & Encoding.JSON:
            encoded_data.update(cls.encode_json(
                command=command,
                data=data,
                use_variable_names=use_variable_names,
                filter_values=filter_values
            ))

        if encoding & Encoding.RAW:
            encoded_data.update(cls.encode_raw(
                command=command,
                data=data,
                frame_number=frame_number,
                use_variable_names=use_variable_names,
                filter_values=filter_values
            ))

        return encoded_data

    @classmethod
    def encode_local(cls,
                     command: AnyCommand,
                     data: Optional[CommandData] = None,
                     use_variable_names: bool = False,
                     filter_values: bool = True,
                     frame_number: Optional[int] = None):
        """Shortcut method for local encoding"""
        return cls.encode(cls.default_local_encoding_type,
                          command, data, use_variable_names,
                          filter_values, frame_number)

    @classmethod
    def encode_cloud(cls,
                     command: AnyCommand,
                     data: Optional[CommandData] = None,
                     use_variable_names: bool = False,
                     filter_values: bool = True,
                     frame_number: Optional[int] = None):
        """Shortcut method for cloud encoding"""
        return cls.encode(cls.default_cloud_encoding_type,
                          command, data, use_variable_names,
                          filter_values, frame_number)

    @classmethod
    def decode(cls,
               data: MessageData,
               use_variable_names: bool = False,
               filter_values: bool = True) -> Tuple[Command, Dict[str, Any], Optional[int]]:
        """
        Decode message using given arguments.
        :param data: Input data
        :param use_variable_names: Use variable names in resulting decoded data
        :param filter_values: Convert values from device format to local format
        :return: Dictionary of data decoded from response
        """
        if 'raw' in data:
            command, data, frame_number = cls.decode_raw(
                raw=data,
                use_variable_names=use_variable_names,
                filter_values=filter_values
            )

        else:
            frame_number = None
            command, data = cls.decode_json(
                json=data,
                use_variable_names=use_variable_names,
                filter_values=filter_values
            )

        return command, data, frame_number

    @classmethod
    def encode_raw(cls, command: Union[CommandID, str], *args, **kwargs) -> Optional[MessageData]:
        """
        Encode data into raw datagram.
        :param command: Command ID / Name
        :return: Raw datagram
        :rtype: str
        """
        if isinstance(command, (CommandID, str)):
            command = cls[command]

        return command.encode_raw(*args, **kwargs)

    @classmethod
    def decode_raw(cls,
                   raw: Union[RawDataType, MessageData],
                   use_variable_names: bool = False,
                   filter_values: bool = True,
                   ignore_extra: bool = False) -> Tuple[Command, Dict[str, Any], int]:
        """
        Decode raw datagram
        :param raw: Raw datagram
        :param use_variable_names: Use variable names as data keys
        :param filter_values: Apply filters to values
        :param ignore_extra:
        :return: command object, dictionary of values, frame number
        :rtype: (Command, dict[str, Any], int)
        """
        raw_bytearray = Command.convert_raw_data(raw)
        command_id = Command.get_command_id_from_raw(raw_bytearray, validate=True)
        command = cls[command_id]

        if raw_bytearray[2] != command.frame_type.value:
            raise CommandDataInvalidFrameTypeException(raw)

        frame_number = raw_bytearray[3]
        argument_values = command.decode_arguments_raw(
            data=raw_bytearray,
            use_variable_names=use_variable_names,
            filter_values=filter_values,
            ignore_extra=ignore_extra
        )

        return command, argument_values, frame_number

    @classmethod
    def encode_json(cls, command: AnyCommand, *args, **kwargs) -> MessageData:
        """
        Encode command via JSON
        :param command: Command ID / Name
        :param args:
        :param kwargs:
        :return:
        """
        if isinstance(command, (int, str)):
            command = cls[command]
        return command.encode_json(*args, **kwargs)

    @classmethod
    def decode_json(cls,
                    json: Union[str, MessageData],
                    use_variable_names: bool = False,
                    filter_values: bool = True) -> Tuple[Command, Dict[str, Any]]:
        """
        Decode JSON data.

        :param json: (optionally decoded) JSON string
        :param use_variable_names: Use variable names instead of argument names
        :param filter_values: Apply variable filters
        :return: command object, dictionary of values
        """
        json_dict = Command.convert_json_data(json)
        command_id = Command.get_command_id_from_json(json_dict, validate=True)
        command = cls[command_id]

        argument_values = command.decode_arguments_json(
            data=json_dict,
            use_variable_names=use_variable_names,
            filter_values=filter_values
        )

        return command, argument_values
