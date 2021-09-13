# -*- coding: utf-8 -*-
# pylint: disable=too-many-arguments
"""Protocol class module for Hekr API"""
__all__ = [
    'RawProtocol',
    'DictProtocol',
    'BaseProtocol',
    'TO_FLOAT',
    'TO_BOOL',
    'TO_STR',
    'TO_SIGNED_FLOAT',
    'signed_float_converter'
]
from json import dumps as json_dumps
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Union, List, Dict, Optional, Callable, Mapping, Any

from .command import Command
from .const import FRAME_START_IDENTIFICATION
from .exceptions import CommandNotFoundException, HekrTypeError, HekrValueError, InvalidMessagePrefixException, \
    InvalidMessageLengthException, InvalidMessageChecksumException, InvalidMessageFrameTypeException
from .types import CommandData, AnyCommand, DecodeResult

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
        return type(obj)(
            (remove_none(k), remove_none(v))
            for k, v in obj.items() if k is not None and v is not None
        )
    else:
        return obj


class BaseProtocol(ABC):
    def __init__(self, *args, compatibility_checker: Optional[Callable[['Device'], bool]] = None, name: Optional[str] = None):
        """
        Protocol definition constructor.

        :param args: Variable-length of arguments, `Command` objects.
        """
        self.commands = list(args)
        self.name = name or "unnamed protocol"

        self.compatibility_checker = compatibility_checker

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}:\"{self.name}\", {len(self.commands)} commands>"

    def __str__(self) -> str:
        return repr(self)

    @property
    def commands(self) -> List[Command]:
        """
        Commands list getter.

        :return: List of commands.
        :rtype: list[Command]
        """
        return self.__commands

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

        self.__commands = value

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

    def is_device_compatible(self, device: 'Device') -> bool:
        """
        Detects whether passed device is compatible with given protocol.
        :param device:
        :return:
        """
        if self.compatibility_checker:
            return self.compatibility_checker(device)
        raise NotImplementedError

    def get_command_by_id(self, command_id: int) -> Command:
        """
        Get command definition object by its ID.

        :param command_id: Command ID
        :return: `Command` object
        :rtype: Command
        :raises:
            CommandNotFoundException: Command definition not found within protocol
        """
        for command in self.__commands:
            if command.command_id == command_id:
                return command

        raise CommandNotFoundException(command_id)

    def get_command_by_name(self, name: str) -> Command:
        """
        Get command definition object by its name.

        :param name: Command name
        :return: `Command` object
        :rtype: Command
        :raises:
            CommandNotFoundException: Command definition not found within protocol
        """
        for command in self.__commands:
            if command.name == name:
                return command

        raise CommandNotFoundException(name)

    def get_command(self, command: AnyCommand) -> Command:
        """
        Get command by its ID/name (or cycle-return `Command` object).

        :param command: Command ID/name, `Command` object
        :type command: int, str, Command
        :return:
        :raises:
            HekrTypeError: Bad value type for `command` argument
        """
        if isinstance(command, Command):
            return command
        if isinstance(command, int):
            return self.get_command_by_id(command)
        if isinstance(command, str):
            return self.get_command_by_name(command)

        raise TypeError(
            "Argument 'command' (type %s) does not evaluate to any supported command type" %
            command)

    @abstractmethod
    def decode(
        self,
        data: Mapping[str, Any],
        use_variable_names: bool = False,
        filter_values: bool = True
    ) -> DecodeResult:
        """
        Decode response.
        :param raw: Raw datagram
        :param use_variable_names: Use variable names as data keys
        :param filter_values: Apply filters to values
        :type: protocol: Protocol
        :type: raw: str, bytes, bytearray
        :type: use_variable_names: bool
        :type: filter_values: bool
        :return: command object, dictionary of values, frame number
        :rtype: (Command, dict[str, Any], int)
        """
        raise NotImplementedError

    @abstractmethod
    def encode(self, command: AnyCommand, data: Mapping[str, Any], frame_number: int = 1, use_variable_names: bool = False, filter_values: bool = True) -> Dict[str, Any]:
        """
        Encode data into request.
        :param command: Command object/ID/name
        :param data: Dictionary of values
        :param frame_number: Frame number
        :param use_variable_names: Use variable names as data keys
        :param filter_values: Apply filters to values
        :return: Encoded request
        """
        raise NotImplementedError


class RawProtocol(BaseProtocol):
    """ Protocol definition class """

    def decode(
        self,
        data: Union[Mapping[str, Any], str, bytes, bytearray],
        use_variable_names: bool = False,
        filter_values: bool = True
    ) -> DecodeResult:
        if isinstance(data, Mapping):
            if "raw" not in data:
                raise ValueError("mapping does not contain \"raw\" key")
            return self.decode(data["raw"], use_variable_names=use_variable_names, filter_values=filter_values)
        
        if isinstance(raw, str):
            decoded = bytearray.fromhex(raw)
        elif isinstance(raw, bytes):
            decoded = bytearray(raw)
        elif isinstance(raw, bytearray):
            decoded = raw
        else:
            raise HekrTypeError(variable='raw', expected=[str, bytearray], got=type(raw))

        if decoded[0] != FRAME_START_IDENTIFICATION:
            raise InvalidMessagePrefixException(raw)

        frame_length = decoded[1]
        if frame_length != len(decoded):
            raise InvalidMessageLengthException(raw)

        checksum = decoded[-1]
        current_checksum = sum(decoded[:-1]) % 0x100
        if checksum != current_checksum:
            raise InvalidMessageChecksumException(raw)

        frame_type = decoded[2]
        command_id = decoded[4]
        command = self.get_command_by_id(command_id)
        if frame_type != command.frame_type.value:
            raise InvalidMessageFrameTypeException(raw)

        frame_number = decoded[3]

        data = command.decode_raw(decoded[5:-1], use_variable_names, filter_values)

        return command, data, frame_number

    def encode(
        self,
        command: AnyCommand,
        data: CommandData = None,
        frame_number: int = 1,
        use_variable_names: bool = False,
        filter_values: bool = True
    ) -> Dict[str, Any]:

        command = self.get_command(command)

        if not data:
            data = {}

        encoded_command = command.encode_raw(
            data=data,
            use_variable_names=use_variable_names,
            filter_values=filter_values
        )

        raw = bytearray()
        raw.append(FRAME_START_IDENTIFICATION)
        raw.append(command.frame_type.value)
        raw.append(frame_number % 256)
        raw.append(command.command_id)
        raw.extend(encoded_command)
        raw.insert(1, len(raw) + 2)
        raw.append(sum(raw) % 0x100)

        return {"raw": raw.hex().upper()}


class DictProtocol(BaseProtocol):
    def decode(
        self,
        data: Mapping[str, Any],
        use_variable_names=False,
        filter_values=True
    ) -> DecodeResult:
        command_id = data.get("cmdId")
        
        if command_id is None:
            raise InvalidDataMissingKeyException(data_key="cmdId")
        
        command = self.get_command(int(command_id))

        data = command.decode_dict(
            data,
            use_variable_names=use_variable_names,
            filter_values=filter_values,
        )
        
        return command, data, -1

    def encode(
        self,
        command: AnyCommand,
        data: CommandData = None,
        frame_number: int = 1,
        use_variable_names=False,
        filter_values=True
    ) -> Dict[str, Any]:
        command = self.get_command(command)

        if not data:
            data = {}
        
        return command.encode_dict(
            data,
            use_variable_names=use_variable_names,
            filter_values=filter_values,
        )
