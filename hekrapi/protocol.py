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
    'signed_float_converter'
]

import copy
from enum import Flag, auto, IntEnum
from functools import partial
from json import dumps as json_dumps, loads as json_loads, JSONDecodeError
from typing import TYPE_CHECKING, Union, List, Dict, Optional, Callable, Any, Tuple

from .const import FRAME_START_IDENTIFICATION, FrameType
from .exceptions import CommandNotFoundException, HekrTypeError, HekrValueError, InvalidMessagePrefixException, \
    InvalidMessageLengthException, InvalidMessageChecksumException, InvalidMessageFrameTypeException, \
    InvalidDataMissingKeyException, InvalidDataLessThanException, InvalidDataGreaterThanException
from .types import CommandData, AnyCommand, DecodeResult, MessageEncoded, MessageData, RawDataType, JSONDataType

if TYPE_CHECKING:
    from .device import Device


def signed_float_converter(threshold, type_input=int, type_output=float):
    """ Generates a signed float converter. """
    def convert_input(value):
        """ Adds negative value to threshold to restore original """
        value = type_input(value)
        return threshold-value if value < 0 else value

    def convert_output(value):
        """ Inverts sign if original is equal to or greater than threshold """
        value = type_output(value)
        return value if value < threshold else threshold-value

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


class Encoding(Flag):
    RAW = auto()
    JSON = auto()


ArgumentType = Callable[[Any], Any]


class Argument:
    """Argument class for HekrAPI"""

    def __init__(self, name: str,
                 value_type: Union[Tuple[ArgumentType, ArgumentType], ArgumentType] = str,
                 length: Optional[int] = None,
                 variable: Optional[str] = None,
                 multiplier: Optional[Union[int, float]] = None,
                 decimals: Optional[int] = None,
                 value_min: Optional[Union[int, float]] = None,
                 value_max: Optional[Union[int, float]] = None,
                 value_default: Optional[Any] = None
                 ):
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

    def __repr__(self):
        """Overloaded argument definition

        Returns:
            str -- Human-friendly argument definition
        """
        return '<{}({})>'.format(self.__class__.__name__, self.name)

    @property
    def decimals(self) -> int:
        """Getter for decimals count to round result to

        Extracts decimal point from multiplier unless a specific value is set
        via getter method.

        Returns:
            int -- Floating point digits
        """
        if self.__decimals is None:
            decimals = str(self.multiplier)[::-1].find('.')
            return 0 if decimals < 0 else decimals

        return self.__decimals

    @decimals.setter
    def decimals(self, value):
        """Getter for decimals count to round result to"""
        self.__decimals = value

    @property
    def variable(self) -> str:
        """Getter for variable name

        Variable name is used in several encoding/decoding scenarios.
        It defaults to `name` attribute if not set explicitly.

        Returns:
            str -- Variable name
        """
        if self.__variable is None:
            return self.name
        return self.__variable

    @variable.setter
    def variable(self, value):
        """Setter for variable name"""
        self.__variable = value


class Command:
    """Base command class for HekrAPI"""
    def __init__(self,
                 command_id: int,
                 frame_type: FrameType = FrameType.SEND,
                 name: str = None,
                 arguments: list = None,
                 response_command_id: int = None,
                 invoke_command_id: int = None):
        """
        Command class constructor.

        :param command_id: Command identifier for datagrams.
        :param frame_type: Frame type for command.
        :param name: Command name (rarely used externally).
        :param arguments: List of arguments bound to command.
        :param response_command_id: Command ID to wait for response from.
        :param invoke_command_id: Command ID to expect invocation from.
        :type command_id: int
        :type frame_type: FrameType
        :type name: str
        :type arguments: list
        :type response_command_id: int
        """

        # circular checking prevents following private attributes
        # from being created automatically
        self.__response_command_id = None
        self.__invoke_command_id = None
        self.__frame_type = None

        self.command_id = command_id
        self.name = name
        self.frame_type = frame_type
        self.response_command_id = response_command_id
        self.invoke_command_id = invoke_command_id
        self.arguments = arguments

    def __repr__(self) -> str:
        """
        Pythonize command object representation.

        :return: Command representation (Python-like)
        :rtype: str
        """
        return '<{}({}, {}, {})>'.format(
            self.__class__.__name__,
            '"' + self.name + '"' if self.name is not None else None,
            self.command_id,
            self.frame_type.name
        )

    def __str__(self) -> str:
        """
        Command name alternative getter.

        :return: Command name
        :rtype: str
        """
        return self.name

    def __int__(self) -> int:
        """
        Command ID alternative getter.

        :return:
        """
        return self.command_id

    @property
    def command_id(self) -> int:
        """
        Command ID getter.

        :return: Command ID.
        :rtype: int
        """
        return self.__command_id

    @command_id.setter
    def command_id(self, value: int) -> None:
        """
        Command ID setter.

        :param value: Command ID.
        :raises:
            HekrTypeError: Raised when the value fed is not an integer.
            HekrValueError: Raised when a value is out of bounds of bytes constraint.
        """
        if not isinstance(value, int):
            raise HekrTypeError(variable='command_id',
                                expected=int,
                                got=type(value))
        elif 255 < value < 0:
            raise HekrValueError(variable='command_id',
                                 expected='integer from 0 to 255',
                                 got=value)
        self.__command_id = value

    @property
    def frame_type(self) -> FrameType:
        """
        Getter for `frame_type` attribute.

        :return: Frame type for command.
        :rtype: FrameType
        """
        return self.__frame_type

    @frame_type.setter
    def frame_type(self, value: FrameType) -> None:
        """
        Setter for `frame_type` attribute.

        Coerces any incoming value on invocation to `FrameType` class instances.
        Throws exceptions when incorrect data is being fed.

        :param value: Frame type for command.
        :raises:
            HekrTypeError: Raised when the value is not coercible to a `FrameType` instance
            HekrValueError: Raised when the value is not `FrameType.SEND` when `response_command_id` attribute is set.
            HekrValueError: Raised when the value is not `FrameType.RECEIVE` when `invoke_command_id` attribute is set.
        """
        try:
            if value is None:
                new_frame_type = FrameType.SEND
            elif isinstance(value, str):
                new_frame_type = FrameType[value.upper()]
            else:
                new_frame_type = FrameType(value)
        except KeyError:
            # noinspection PyTypeChecker
            raise HekrValueError(variable='frame_type',
                                 expected=', '.join(map(lambda x: "'"+x.name.lower()+"'", FrameType)) +
                                          " (case-insensitive)",
                                 got=value)
        except ValueError:
            raise HekrTypeError(variable='frame_type',
                                expected='coercible to `%s`' % FrameType.__name__,
                                got=type(value))

        if new_frame_type != FrameType.SEND and self.response_command_id is not None:
            raise HekrValueError(variable='frame_type',
                                 expected='`%s` due to `response_command_id` being set' % FrameType.SEND,
                                 got=new_frame_type)

        if new_frame_type != FrameType.RECEIVE and self.invoke_command_id is not None:
            raise HekrValueError(variable='frame_type',
                                 expected='`%s` due to `invoke_command_id` being set' % FrameType.RECEIVE,
                                 got=new_frame_type)

        self.__frame_type = new_frame_type

    @property
    def arguments(self) -> List[Argument]:
        """
        Arguments list getter.
        :return: List of arguments.
        :rtype: list[Argument]
        """
        return self.__arguments

    @arguments.setter
    def arguments(self, value: List[Argument]) -> None:
        """
        Arguments list setter.

        Throws exceptions when incorrect data is being fed.

        :param value: List of arguments for command.
        :raises:
            HekrTypeError: Raised when one or more values is not of `Argument` type.
            HekrTypeError: Raised when arguments list is fed something other than lists.
        """
        if isinstance(value, list):
            invalid_types = [type(x) for x in value if not isinstance(x, Argument)]

            if invalid_types:
                raise HekrTypeError(variable='arguments list',
                                    expected=Argument,
                                    got=invalid_types)
        elif value is not None:
            raise HekrTypeError(variable='arguments list',
                                expected=[list, type(None)],
                                got=type(value))

        self.__arguments = value or []

    @property
    def invoke_command_id(self) -> int:
        """
        Invoke command ID getter.

        :return: int
        """
        return self.__response_command_id

    @invoke_command_id.setter
    def invoke_command_id(self, value):
        if value is not None:
            if self.frame_type is None or self.frame_type != FrameType.RECEIVE:
                raise HekrValueError(variable='invoke_command_id',
                                     expected='`None` due to `frame_type` not being set to `FrameType.RECEIVE` '
                                              '(current value `%s`)' % self.frame_type,
                                     got=value)
            elif not isinstance(value, int):
                raise HekrTypeError(variable='invoke_command_id',
                                    expected=int,
                                    got=type(value))
            elif value < 0:
                raise HekrValueError(variable='invoke_command_id',
                                     expected='>= 0',
                                     got=value)
        self.__invoke_command_id = value

    @property
    def response_command_id(self) -> int:
        """
        Response command ID getter.

        :return: int
        """
        return self.__response_command_id

    @response_command_id.setter
    def response_command_id(self, value):
        if value is not None:
            if self.frame_type is None or self.frame_type != FrameType.SEND:
                raise HekrValueError(variable='response_command_id',
                                     expected='`None` due to `frame_type` not being set to `FrameType.SEND` '
                                              '(current value `%s`)' % self.frame_type,
                                     got=value)
            elif not isinstance(value, int):
                raise HekrTypeError(variable='response_command_id',
                                    expected=int,
                                    got=type(value))
            elif value < 0:
                raise HekrValueError(variable='response_command_id',
                                     expected='>= 0',
                                     got=value)
        self.__response_command_id = value

    @staticmethod
    def _process_arguments(callback: Callable[[Union[str, Argument], Any], Any], arguments: List[Argument],
                           data: Optional[CommandData] = None, use_variable_names: bool = False,
                           filter_values: bool = True, ignore_extra: bool = False,
                           pass_argument: bool = False, raise_for_error: bool = True) -> bool:
        if data is None:
            data = dict()

        argument_keys = set()

        for argument in arguments:
            key = argument.variable if use_variable_names else argument.name
            value_input = data.get(key, None)

            if value_input is None:
                if argument.value_default is None:
                    if raise_for_error:
                        raise InvalidDataMissingKeyException(data_key=key)
                    return None
                value_input = argument.value_default

            argument_keys.add(key)

            if argument.value_min is not None and argument.value_min > value_input:
                if raise_for_error:
                    raise InvalidDataLessThanException(
                        data_key=key,
                        value=value_input,
                        value_min=argument.value_min)
                return None

            if argument.value_max is not None and argument.value_max < value_input:
                if raise_for_error:
                    raise InvalidDataGreaterThanException(
                        data_key=key,
                        value=value_input,
                        value_max=argument.value_max)
                return None

            if filter_values:
                if argument.multiplier:
                    value_input /= argument.multiplier

                value_input = argument.type_input(value_input)

            callback(argument if pass_argument else argument.variable, value_input)

        if ignore_extra:
            extra_keys = data.keys() - argument_keys
            if extra_keys:
                if raise_for_error:
                    raise HekrValueError(variable='data',
                                         expected='dict[%s]' % ', '.join(extra_keys),
                                         got=', '.join(map(str, data.keys())))
                return False

        return True

    # Command encoding/decoding: Raw
    def encode_arguments_raw(self, data: Optional[CommandData] = None, use_variable_names: bool = False,
                             filter_values: bool = True, raise_for_error: bool = True) \
            -> Optional[bytearray]:
        """Encode arguments into an array of bytes."""
        result = bytearray()
        appender = partial(append_bytes_to_array, result)

        # noinspection PyTypeChecker
        if not Command._process_arguments(callback=appender, arguments=self.arguments, data=data,
                                          use_variable_names=use_variable_names, filter_values=filter_values,
                                          pass_argument=True, raise_for_error=raise_for_error):
            return None

        return result

    def decode_arguments_raw(self, data: bytes, use_variable_names: bool = False, filter_values: bool = True,
                             ignore_extra: bool = False, raise_for_error: bool = False) -> Optional[CommandData]:
        """Decode passed data"""
        decoded = data[5:-1]

        result = {}
        current_pos = 0
        data_length = len(decoded)
        for argument in self.arguments:
            key = argument.variable if use_variable_names else argument.name

            next_pos = current_pos + argument.length
            if next_pos > data_length:
                if raise_for_error:
                    raise InvalidDataMissingKeyException(data_key=key)
                return None

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
            if raise_for_error:
                raise HekrValueError(variable='len(data)', expected=current_pos, got=data_length)
            return None

        return result

    def encode_raw(self, data: Optional[CommandData] = None, frame_number: int = 1, use_variable_names: bool = False,
                   filter_values: bool = True, only_datagram: bool = False, raise_for_error: bool = True) \
            -> Optional[Union[Dict[str, Any], str]]:
        encoded_arguments = self.encode_arguments_raw(
            data=data,
            use_variable_names=use_variable_names,
            filter_values=filter_values,
            raise_for_error=raise_for_error
        )

        if encoded_arguments is None:
            return None

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
    def convert_raw_data(data: Union[RawDataType, MessageData], raise_for_error: bool = True) -> Optional[bytearray]:
        if isinstance(data, dict):
            data = data.get('raw')
            if not data:
                if raise_for_error:
                    raise HekrValueError(variable='data', got=data, expected='Dictionary with "raw" key')
                return None

        if isinstance(data, bytearray):
            return data

        elif isinstance(data, str):
            return bytearray.fromhex(data)

        elif isinstance(data, bytes):
            return bytearray(data)

        if raise_for_error:
            raise HekrTypeError(variable='raw', expected=[str, bytes, bytearray], got=type(data))
        return None

    @staticmethod
    def validate_raw_datagram(decoded: bytearray, raise_for_error: bool = True) -> bool:
        # Common prefix is located at first byte
        if decoded[0] != FRAME_START_IDENTIFICATION:
            if raise_for_error:
                raise InvalidMessagePrefixException(decoded)
            return False

        # Frame length is located at second byte
        frame_length = decoded[1]
        if frame_length != len(decoded):
            if raise_for_error:
                raise InvalidMessageLengthException(decoded)
            return False

        # Checksum is located at last byte
        checksum = decoded[-1]
        current_checksum = sum(decoded[:-1]) % 0x100
        if checksum != current_checksum:
            if raise_for_error:
                raise InvalidMessageChecksumException(decoded)
            return False

        return True

    @staticmethod
    def get_command_id_from_raw(data: Union[RawDataType, MessageData], validate: bool = True,
                                raise_for_error: bool = True) -> Optional[int]:
        """
        Helper method to retrieve command ID from raw datagram.
        :param raise_for_error:
        :param data:
        :param validate:
        :return: int - Command ID | None - error (if raise_for_error is True)
        """
        decoded = data if isinstance(data, bytearray) \
            else Command.convert_raw_data(data, raise_for_error=raise_for_error)

        if decoded is None:
            # It would have raised an exception by this point
            return None

        if validate and not Command.validate_raw_datagram(decoded, raise_for_error=raise_for_error):
            # It would have raised an exception by this point
            return None

        # Command ID is located at 5th byte
        return decoded[4]

    # Command encoding/decoding: JSON
    def encode_arguments_json(self, data: CommandData, use_variable_names: bool = False, filter_values: bool = True,
                              ignore_extra: bool = False, raise_for_error: bool = True) -> Optional[Dict[str, Any]]:
        result = dict()
        if not Command._process_arguments(callback=result.__setitem__, arguments=self.arguments, data=data,
                                          use_variable_names=use_variable_names, filter_values=filter_values,
                                          pass_argument=False, ignore_extra=ignore_extra,
                                          raise_for_error=raise_for_error):
            return None

        return result

    def decode_arguments_json(self, data: Dict[str, Any], use_variable_names: bool = False, filter_values: bool = True,
                              ignore_extra: bool = False, raise_for_error: bool = True) -> Optional[CommandData]:
        """Decode passed data"""
        if len(self.arguments) > len(data) or not ignore_extra and len(self.arguments) < len(data):
            if raise_for_error:
                raise HekrValueError(variable='data', expected=len(self.arguments), got=len(data))
            return None

        result = {}
        for argument in self.arguments:
            key = argument.variable if use_variable_names else argument.name

            if argument.variable not in data:
                if raise_for_error:
                    raise InvalidDataMissingKeyException(data_key=key)
                return None

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
                    filter_values: bool = True, raise_for_error: bool = True) -> Optional[MessageEncoded]:
        encoded_arguments = self.encode_arguments_json(
            data=data,
            use_variable_names=use_variable_names,
            filter_values=filter_values,
            raise_for_error=raise_for_error
        )
        encoded_arguments["cmdId"] = self.command_id

        return encoded_arguments

    @staticmethod
    def convert_json_data(data: Union[str, MessageData], raise_for_error: bool = True) -> Optional[JSONDataType]:
        if isinstance(data, str):
            try:
                return json_loads(data)

            except JSONDecodeError:
                if raise_for_error:
                    raise HekrValueError(variable='data', expected=['JSON array', 'dictionary'], got=data)
                return None

        elif isinstance(data, dict):
            return data

        if raise_for_error:
            raise HekrTypeError(variable='data', expected=[str, dict], got=type(data))
        return None

    @staticmethod
    def validate_json_dict(data: JSONDataType, raise_for_error: bool = True) -> bool:
        skip_keys_length = 0
        if 'raw' in data:
            skip_keys_length += 1

        if 'cmdId' not in data:
            if raise_for_error:
                raise HekrValueError(variable='data[cmdId]', expected='command ID', got=None)
            return False

        if not len(data) - skip_keys_length:
            if raise_for_error:
                raise HekrValueError(variable='data', expected='data', got='empty dictionary')
            return False

        return True

    @staticmethod
    def get_command_id_from_json(data: Union[str, MessageData], validate: bool = True, raise_for_error: bool = True) \
            -> Optional[int]:
        decoded = data if isinstance(data, dict) else Command.convert_json_data(data, raise_for_error=raise_for_error)

        if decoded is None:
            # It would have raised an exception by this point
            return None

        if validate and not Command.validate_json_dict(data):
            # It would have raised an exception by this point
            return None

        return data['cmdId']


def append_bytes_to_array(byte_result: bytearray, argument: Argument, value: int):
    byte_result += value.to_bytes(
        argument.length,
        byteorder='big',
        signed=False
    )


class Protocol:
    """ Protocol definition class """

    def __init__(self, *args, compatibility_checker: Optional[Callable[['Device'], bool]] = None,
                 default_encoding_type: Optional[Union[Encoding, int]] = None, default_port: Optional[int] = None):
        """
        Protocol definition constructor.

        :param args: Variable-length of arguments, `Command` objects.
        """
        self.commands = list(args)

        self.compatibility_checker = compatibility_checker
        self.default_port = default_port

        if default_encoding_type is None:
            self.default_encoding_type = Encoding.RAW
        elif isinstance(default_encoding_type, int):
            self.default_encoding_type = Encoding(default_encoding_type)
        else:
            self.default_encoding_type = default_encoding_type

    def __copy__(self):
        """
        Return protocol copy.
        :return:
        """
        return Protocol(*self._commands,
                        compatibility_checker=self.compatibility_checker,
                        default_encoding_type=self.default_encoding_type,
                        default_port=self.default_port)

    def __getattr__(self, item):
        """
        Retrieves prepared encoder for command.
        :param item:
        :return:
        """
        command = self.get_command_by_name(item, raise_for_error=False)

        if command is not None:
            def encode_command(frame_number: int = 1,
                               use_variable_names: bool = False,
                               filter_values: bool = True,
                               encoding_type: Optional[Encoding] = None,
                               **kwargs):
                """
                Encode command
                :param frame_number: Frame number
                :param use_variable_names: Use variable names in
                :param filter_values:
                :param encoding_type:
                :param kwargs:
                :return:
                """
                return self.encode(
                    command=command,
                    data=dict(kwargs),
                    frame_number=frame_number,
                    use_variable_names=use_variable_names,
                    filter_values=filter_values,
                    encoding_type=encoding_type
                )

            return encode_command

        raise AttributeError('Attribute "%s" not found in %s' % (item, self))

    def __getitem__(self, key: Union[int, str]) -> Command:
        """
        Retrieves command definition by name or identifier via square-bracket accessor.

        :param key: Command identifier (name or ID)
        :type key: int, str
        :return: Command object
        :raises:
            CommandNotFoundException: if command is not found.
        """
        return self.get_command(key)

    @property
    def commands(self) -> List[Command]:
        """
        Commands list getter.

        :return: List of commands.
        :rtype: list[Command]
        """
        return self._commands

    @commands.setter
    def commands(self, value: List[Command]) -> None:
        """
        Commands list setter.

        Checks whether the value passed is of `list` type and that all elements of the list
        are of `Command` type.
        :param value: List of commands
        :raises:
            HekrTypeError: Raised when passed value is of a different type than `list`
            HekrTypeError: Raised when passed list contains elements of different type(s) than `list`
        """
        if not isinstance(value, list):
            raise HekrTypeError(variable='commands', expected=list, got=type(value))

        invalid_types = [
            type(x) for x in value
            if not isinstance(x, Command)
        ]
        if invalid_types:
            raise HekrTypeError(variable='commands', expected=Command, got=invalid_types)

        self._commands = value

    def extend(self, *args: Command, ignore_names: bool = False) -> 'Protocol':
        """
        Create protocol extension.
        :param args: New commands
        :param ignore_names: Ignore name collisions
        :return:
        """
        new_protocol = copy.copy(self)
        new_protocol.update(*args, ignore_names=ignore_names)

        return new_protocol

    def update(self, *args: Command, ignore_names: bool = False) -> None:
        """
        Update commands list
        :param args: New commands
        :param ignore_names: Ignore name collisions
        :return:
        """
        resulting_commands = {command.command_id: command for command in self._commands}
        new_commands_by_id = {command.command_id: command for command in args}
        resulting_commands.update(new_commands_by_id)

        resulting_commands_list = list(resulting_commands.values())

        if not ignore_names:
            new_command_names = [command.name for command in args]
            resulting_commands_list = [
                command for command in resulting_commands_list
                if command.name not in new_command_names
                or command.command_id in new_commands_by_id
            ]

        self.commands = resulting_commands_list

    def encode(self,
               command: AnyCommand,
               data: Optional[CommandData] = None,
               frame_number: int = 1,
               use_variable_names: bool = False,
               filter_values: bool = True,
               encoding_type: Optional[Encoding] = None,
               raise_for_error: bool = True) -> Optional[MessageData]:
        """
        General encoding for protocol.
        :param command: Command object/ID/Name
        :param data:
        :param frame_number:
        :param use_variable_names:
        :param filter_values:
        :param encoding_type:
        :return:
        """
        command = self.get_command(command, raise_for_error=raise_for_error)

        if command is None:
            return None

        if encoding_type is None:
            encoding_type = self.default_encoding_type

        elif not isinstance(encoding_type, Encoding):
            if raise_for_error:
                raise HekrTypeError(variable='encoding_type', expected=Encoding, got=type(encoding_type))
            return None

        encoded_data = dict()
        if encoding_type & Encoding.JSON:
            encoded_data.update(self.encode_json(
                command=command,
                data=data,
                use_variable_names=use_variable_names,
                filter_values=filter_values
            ))

        if encoding_type & Encoding.RAW:
            encoded_data.update(self.encode_raw(
                command=command,
                data=data,
                frame_number=frame_number,
                use_variable_names=use_variable_names,
                filter_values=filter_values
            ))

        return encoded_data

    def decode(self,
               data: MessageData,
               use_variable_names: bool = False,
               filter_values: bool = True,
               encoding_type: Optional[Encoding] = None) -> DecodeResult:
        """
        Decode data.
        :param data:
        :param use_variable_names:
        :param filter_values:
        :param encoding_type:
        :return:
        """
        if encoding_type is None:
            encoding_type = self.default_encoding_type

        if encoding_type & Encoding.RAW:
            decoder = self.decode_raw

        elif encoding_type & Encoding.JSON:
            decoder = self.decode_transparent_json

        else:
            raise HekrValueError(variable='encoding_type', expected='type(Encoding)', got=encoding_type)

        return decoder(
            data=data,
            use_variable_names=use_variable_names,
            filter_values=filter_values
        )

    def encode_raw(self, command: Command, *args, raise_for_error: bool = True, **kwargs) -> Optional[MessageData]:
        """
        Encode data into raw datagram.
        :param raise_for_error:
        :param command: Command object/ID/Name
        :return: Raw datagram
        :rtype: str
        """
        command = self.get_command(command, raise_for_error=raise_for_error)

        if command is None:
            return None

        return command.encode_raw(*args, raise_for_error=raise_for_error, **kwargs)

    def decode_raw(self,
                   data: Union[RawDataType, MessageData],
                   use_variable_names: bool = False,
                   filter_values: bool = True,
                   raise_for_error: bool = True) -> Optional[DecodeResult]:
        """
        Decode raw datagram
        :param data: Raw datagram
        :param use_variable_names: Use variable names as data keys
        :param filter_values: Apply filters to values
        :param raise_for_error:
        :return: command object, dictionary of values, frame number
        :rtype: (Command, dict[str, Any], int) | None - error (if raise_for_error is True)
        """
        decoded = Command.convert_raw_data(data, raise_for_error=raise_for_error)
        if decoded is None:
            return None

        command_id = Command.get_command_id_from_raw(decoded, raise_for_error=raise_for_error)
        if command_id is None:
            return None

        command = self.get_command_by_id(command_id, raise_for_error=raise_for_error)
        if command is None:
            return None

        if decoded[2] != command.frame_type.value:
            if raise_for_error:
                raise InvalidMessageFrameTypeException(data)
            return None

        frame_number = decoded[3]

        data = command.decode_arguments_raw(decoded, use_variable_names, filter_values, raise_for_error=raise_for_error)

        return command, data, frame_number

    def encode_json(self, command: Command, *args, **kwargs) -> MessageData:
        command = self.get_command(command)
        return command.encode_json(*args, **kwargs)

    def is_device_compatible(self, device: 'Device') -> bool:
        """
        Detects whether passed device is compatible with given protocol.
        :param device:
        :return:
        """
        if self.compatibility_checker:
            return self.compatibility_checker(device)
        raise NotImplementedError

    def get_command_by_id(self, command_id: int, raise_for_error: bool = True) -> Optional[Command]:
        """
        Get command definition object by its ID.

        :param command_id: Command ID
        :return: Command object
        :param raise_for_error: Raise exception on command not being found
        :rtype: Command
        :raises:
            CommandNotFoundException: Command definition not found within protocol
        """
        for command in self._commands:
            if command.command_id == command_id:
                return command

        if raise_for_error:
            raise CommandNotFoundException(command_id)
        return None

    def get_command_by_name(self, name: str, raise_for_error: bool = True) -> Optional[Command]:
        """
        Get command definition object by its name.

        :param name: Command name
        :param raise_for_error: Raise exception on command not being found
        :return: Command object
        :rtype: Command
        :raises:
            CommandNotFoundException: Command definition not found within protocol
        """
        for command in self._commands:
            if command.name == name:
                return command

        if raise_for_error:
            raise CommandNotFoundException(name)
        return None

    def get_command(self, command: AnyCommand, raise_for_error: bool = True) -> Optional[Command]:
        """
        Get command by its ID/name (or cycle-return `Command` object).

        :param raise_for_error:
        :param command: Command ID/name, `Command` object
        :type command: int, str, Command
        :return:
        :raises:
            HekrTypeError: Bad value type for `command` argument
        """
        if isinstance(command, Command):
            return command

        if isinstance(command, int):
            return self.get_command_by_id(command, raise_for_error=raise_for_error)

        if isinstance(command, str):
            return self.get_command_by_name(command, raise_for_error=raise_for_error)

        if raise_for_error:
            raise TypeError(
                "Argument 'command' (type %s) does not evaluate to any supported command type" %
                command)
        return None

    def get_definition_dict(self, filter_empty=True) -> Dict:
        """
        Returns protocol definition as Python dictionary.

        :param filter_empty: Filter out empty values
        :return: Protocol definition
        :rtype: dict
        """
        definition = {
            "commands": [
                {
                    "name": command.name,
                    "command_id": command.command_id,
                    "frame_type": command.frame_type.name.lower(),
                    "response_command_id": command.response_command_id,
                    "arguments": [
                        {
                            "name": argument.name,
                            "variable": argument.variable,
                            "byte_length": argument.length,
                            "type_input": argument.type_input.__name__,
                            "type_output": argument.type_output.__name__,
                            "value_min": argument.value_min,
                            "value_max": argument.value_max,
                            "value_default": argument.value_default,
                            "multiplier": argument.multiplier,
                            "decimals": argument.decimals,
                        }
                        for argument in command.arguments
                    ] if command.arguments else None
                }
                for command in self.commands
            ]
        }
        return remove_none(definition) if filter_empty else definition

    default_serialization_format = 'json'
    serialization_formats = {
        'json': lambda definition: json_dumps(definition, ensure_ascii=False),
    }

    def get_definition_serialized(self, output_format: Optional[str] = None) -> str:
        """
        Returns protocol definition as serialized dictionary.

        :param output_format: Output format
        :type output_format: str
        :return: Serialized definition dictionary
        :rtype: str
        """
        if output_format is None:
            output_format = self.default_serialization_format
        elif output_format not in self.serialization_formats:
            raise HekrValueError(variable='output_format', expected=['json'], got=output_format)

        definition = self.get_definition_dict()

        return self.serialization_formats[output_format](definition)

    def print_definition(self, output_format: Optional[str] = None) -> None:
        """
        Prints protocol definition.

        :param output_format: Output format
        :type: output_format: str
        """
        print(self.get_definition_serialized(output_format=output_format))
