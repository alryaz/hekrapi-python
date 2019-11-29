
from typing import Union
from .command import Command, FrameType, DEFAULT_QUERY_COMMAND
from .exceptions import (
    CommandFailedException,
    CommandNotFoundException
)
from .datagram import encode, decode


class Protocol(object):
    def __init__(self, *args):
        self.__commands = list(args)
        # @TODO: make this more lean or make a generic platform definition
        self.__commands.append(DEFAULT_QUERY_COMMAND)

    def __getitem__(self, key: Union[Command, int, str]):
        return self.get_command(key)

    def print_definition(self, sort=False, prefix: str = ''):
        print(prefix + 'protocol name')
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

    def get_command_by_id(self, id: int) -> Command:
        for command in self.__commands:
            if command.command_id == id:
                return command

        raise CommandNotFoundException(id)

    def get_command_by_name(self, name: str) -> Command:
        for command in self.__commands:
            if command.name == name:
                return command

        raise CommandNotFoundException(name)

    def get_command(self, command: Union[Command, int, str]) -> Command:
        if isinstance(command, int):
            return self.get_command_by_id(command)
        elif isinstance(command, str):
            return self.get_command_by_name(command)
        elif isinstance(command, Command):
            return command

        raise TypeError(
            "Argument 'command' (type %s) does not evaluate to any supported command type" %
            command)
