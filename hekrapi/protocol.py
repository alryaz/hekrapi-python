# -*- coding: utf-8 -*-
# pylint: disable=too-many-arguments
"""Protocol class module for Hekr API"""
from yaml import dump as yaml_dump, load as yaml_load, SafeLoader, SafeDumper
from json import dumps as json_dumps

from typing import Union, List, Dict
from collections import OrderedDict

from .types import (DecodedDataType, DatagramType, CommandSearchIdentifier)
from .command import Command, FrameType
from .exceptions import CommandNotFoundException, HekrTypeError, HekrValueError
from .datagram import encode, decode

def remove_none(obj):
    if isinstance(obj, (list, tuple, set)):
        return type(obj)(remove_none(x) for x in obj if x is not None)
    elif isinstance(obj, dict):
        return type(obj)((remove_none(k), remove_none(v))
        for k, v in obj.items() if k is not None and v is not None)
    else:
        return obj

class Protocol:
    """Protocol class definition for Hekr API"""

    def __init__(self, *args):
        """Protocol class constructor

        Arguments:
            *args {Command} -- Commands included in the protocol
        """
        self.commands = list(args)

    @property
    def commands(self) -> List[Command]:
        """Commands list setter

        Returns:
            List[Command] -- List of commands associated with the protocol
        """
        return self.__commands

    @commands.setter
    def commands(self, value:List[Command]) -> None:
        """Commands list setter

        Checks whether the value passed is of `list` type and that all elements of the list
        are of `Command` type.

        Arguments:
            value {[type]} -- [description]

        Raises:
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

    def __getitem__(self, key: CommandSearchIdentifier) -> Command:
        """Retrieves command with a square bracket accessor

        Arguments:
            key {CommandSearchIdentifier} -- Command ID/name

        Returns:
            Command -- Found command object
        """
        return self.get_command(key)

    def decode(self, raw: DatagramType,
               use_variable_names=False, filter_values=True) -> DecodedDataType:
        """Protocol-oriented datagram decoding

        Provides a wrapper for an out-of-class decoding function from `datagram` submodule.
        The wrapper passes all existing parameters alongside `self` as `protocol` argument.

        Arguments:
            raw {Union[bytearray, str]} -- Raw datagram string

        Keyword Arguments:
            use_variable_names {bool} -- Use variable names as keys with data (default: {False})
            filter_values {bool} -- Filter values (multiply/round) (default: {True})

        Returns:
            DecodedDataType -- Dictionary of result values
        """
        return decode(
            raw=raw,
            protocol=self,
            use_variable_names=use_variable_names,
            filter_values=filter_values
        )

    def encode(self,
               command: Union[int,
                              str,
                              Command],
               data: DecodedDataType,
               frame_number: int,
               use_variable_names=False,
               filter_values=True) -> DatagramType:
        """Protocol-oriented datagram encoding

        Provides a wrapper for an out-of-class encoding function from `datagram` submodule.
        The wrapper searches for a command within the protocol and passes all existing parameters
        alongside the result as `command` argument.

        Arguments:
            command {Union[int,str,Command]} -- Command identifier or object
            data {dict} -- Data dictionary
            frame_number {int} -- Frame number

        Keyword Arguments:
            use_variable_names {bool} -- Use variable names as keys with data (default: {False})
            filter_values {bool} -- Filter values (multiply/round) (default: {True})

        Returns:
            str -- Raw datagram string
        """
        return encode(
            command=self.get_command(command),
            data=data,
            frame_number=frame_number,
            use_variable_names=use_variable_names,
            filter_values=filter_values
        )

    def get_command_by_id(self, command_id: int) -> Command:
        """Get command by its ID

        Arguments:
            command_id {int} -- Command ID to search for

        Raises:
            CommandNotFoundException: Command not found by given ID

        Returns:
            Command -- Command object
        """
        for command in self.__commands:
            if command.command_id == command_id:
                return command

        raise CommandNotFoundException(command_id)

    def get_command_by_name(self, name: str) -> Command:
        """Get command by its name

        Arguments:
            name {str} -- Command name to search for

        Raises:
            CommandNotFoundException: Command not found by given name

        Returns:
            Command -- Command object
        """
        for command in self.__commands:
            if command.name == name:
                return command

        raise CommandNotFoundException(name)

    def get_command(self, command: Union[int, str, Command]) -> Command:
        """Get command by its ID/name (or cycle-return object)

        Arguments:
            command {Union[int, str, Command]} -- Command ID/name/object

        Raises:
            TypeError: Bad argument type provided

        Returns:
            Command -- Command object
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

    def get_definition(self, filter_empty=True):
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

    def print_definition(self, prefix: str = '', format:str='yaml'):
        """Prints protocol definition in YAML format

        Keyword Arguments:
            sort {bool} -- Sort commands by frame types (default: {False})
            prefix {str} -- What to prefix every line with (default: {''})
        """
        definition = self.get_definition()
        if format == 'yaml':
            output = yaml_dump(definition, Dumper=SafeDumper, default_flow_style=False, sort_keys=False)
        elif format == 'json':
            output = json_dumps(definition, ensure_ascii=False)

        print(output)
