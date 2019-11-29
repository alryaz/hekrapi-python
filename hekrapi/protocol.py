# -*- coding: utf-8 -*-
# pylint: disable=too-many-arguments
"""Protocol class module for Hekr API"""
from typing import Union
from .command import Command, FrameType, DEFAULT_QUERY_COMMAND
from .exceptions import CommandNotFoundException
from .datagram import encode, decode


class Protocol:
    """Protocol class definition for Hekr API"""

    def __init__(self, *args):
        """Protocol class constructor

        Arguments:
            *args {Command} -- Commands included in the protocol
        """
        self.__commands = list(args)
        # @TODO: make this more lean or make a generic platform definition
        self.__commands.append(DEFAULT_QUERY_COMMAND)

    def __getitem__(self, key: Union[int, str]):
        """Retrieves command with a square bracket accessor

        Arguments:
            key {Union[int, str]} -- Command ID/name

        Returns:
            Command -- Found command object
        """
        return self.get_command(key)

    def print_definition(self, sort=False, prefix: str = ''):
        """Prints protocol definition in YAML format

        Keyword Arguments:
            sort {bool} -- Sort commands by frame types (default: {False})
            prefix {str} -- What to prefix every line with (default: {''})
        """
        print(prefix + 'protocol:')
        new_prefix = prefix + '  '

        if sort:
            first_command = True
            for frame_type in FrameType:
                command_printed = False

                for command in self.__commands:
                    if command.frame_type == frame_type:
                        if not command_printed:
                            command_printed = True

                        if first_command:
                            first_command = False

                        else:
                            print()

                        command.print_definition(new_prefix)
        else:
            for command in self.__commands:
                command.print_definition(new_prefix)

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
