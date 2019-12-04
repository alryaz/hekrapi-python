# -*- coding: utf-8 -*-
# pylint: disable=too-many-arguments
"""Protocol class module for Hekr API"""
from yaml import dump as yaml_dump, load as yaml_load, SafeLoader, SafeDumper
from json import dumps as json_dumps

from typing import Union, List, Tuple, Dict, Any

from .command import Command
from .exceptions import CommandNotFoundException, HekrTypeError, HekrValueError
from .helpers import datagram_encode, datagram_decode


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


class Protocol:
    """ Protocol definition class """

    def __init__(self, *args):
        """
        Protocol definition constructor.

        :param args: Variable-length of arguments, `Command` objects.
        """
        self.commands = list(args)

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

        invalid_types = [type(x) for x in value
            if not isinstance(x, Command)]
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

    def decode(self,
               raw: Union[str, bytes, bytearray],
               use_variable_names=False,
               filter_values=True) -> Tuple[Command, Dict[str, Any], int]:
        """
        Protocol-bound datagram encoding.

        :param raw: Raw datagram
        :param use_variable_names: Use variable names as data keys
        :param filter_values: Apply filters to values
        :return: command object, dictionary of values, frame number
        :rtype: (Command, dict[str, Any], int)
        """
        return datagram_decode(
            raw=raw,
            protocol=self,
            use_variable_names=use_variable_names,
            filter_values=filter_values
        )

    def encode(self,
               command: Union[int, str, Command],
               data: Dict[str, Any],
               frame_number: int,
               use_variable_names=False,
               filter_values=True) -> str:
        """
        Protocol-bound datagram encoding.

        Provides a wrapper for an out-of-class encoding function from `datagram` submodule.
        The wrapper searches for a command within the protocol and passes all existing parameters
        alongside the result as `command` argument.

        :param command: Command identifier or `Command` object
        :param data: Dictionary of values
        :param frame_number: Frame number
        :param use_variable_names: Use variable names as data keys
        :param filter_values: Apply filters to values
        :return: Raw datagram
        :rtype: str
        """
        return datagram_encode(
            command=self.get_command(command),
            data=data,
            frame_number=frame_number,
            use_variable_names=use_variable_names,
            filter_values=filter_values
        )

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

    def get_command(self, command: Union[int, str, Command]) -> Command:
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
                            "byte_length": argument.byte_length,
                            "type_input": argument.type_input.__name__,
                            "type_output": argument.type_output.__name__,
                            "value_min": argument.value_min,
                            "value_max": argument.value_max,
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

    def get_definition_serialized(self, output_format: str = 'yaml') -> str:
        """
        Returns protocol definition as serialized dictionary.

        :param output_format: Output format
        :type output_format: str
        :return: Serialized definition dictionary
        :rtype: str
        """
        definition = self.get_definition_dict()
        if output_format == 'yaml':
            output = yaml_dump(definition, Dumper=SafeDumper, default_flow_style=False, sort_keys=False)
        elif output_format == 'json':
            output = json_dumps(definition, ensure_ascii=False)
        else:
            raise HekrValueError(variable='output_format', expected=['yaml', 'json'], got=output_format)

        return output

    def print_definition(self, output_format: str = 'yaml') -> None:
        """
        Prints protocol definition.

        :param output_format: Output format
        :type: output_format: str
        """
        print(self.get_definition_serialized(output_format=output_format))
