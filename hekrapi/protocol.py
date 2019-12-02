# -*- coding: utf-8 -*-
# pylint: disable=too-many-arguments
"""Protocol class module for Hekr API"""
from yaml import dump as yaml_dump, load as yaml_load, SafeLoader, SafeDumper
from json import dumps as json_dumps

from typing import Union
from collections import OrderedDict

from .command import Command, FrameType
from .exceptions import CommandNotFoundException
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
    def commands(self):
        return self.__commands

    @commands.setter
    def commands(self, commands):
        if not isinstance(commands, list):
            raise TypeError('Commands list should be of `list` type')

        invalid_types = [str(type(x)) for x in commands
            if not isinstance(x, Command)]
        if invalid_types:
            raise ValueError(
                'Commands list contains values that are not of `%s` type: %s'
                % (Command.__name__, ', '.join(invalid_types)))

        self.__commands = commands

    def __getitem__(self, key: Union[int, str]):
        """Retrieves command with a square bracket accessor

        Arguments:
            key {Union[int, str]} -- Command ID/name

        Returns:
            Command -- Found command object
        """
        return self.get_command(key)

    def decode(self, raw: Union[bytearray, str],
               use_variable_names=False, filter_values=True) -> dict:
        """Protocol-oriented datagram decoding"""
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
               data: dict,
               frame_number: int,
               use_variable_names=False,
               filter_values=True) -> str:
        """Protocol-oriented datagram encoding"""
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
