# -*- coding: utf-8 -*-
"""Command class module for HekrAPI"""

from enum import IntEnum

from .argument import Argument

class FrameType(IntEnum):
    """Datagram frame types (per Hekr documentation)"""
    RECEIVE = 0x01
    SEND = 0x02
    DEVICE = 0xFE
    ERROR = 0xFF

class Command:
    """Command class for HekrAPI"""

    def __init__(self,
                 command_id: int,
                 name: str,
                 frame_type: FrameType,
                 *args: Argument,
                 response_command_id:int=None
                 ):
        """Command class constructor

        Arguments:
            command_id {int} -- Command identifier for datagrams
            name {str} -- Command name for calls
            frame_type {FrameType} -- Command frame type (per Hekr docs)
        """
        self.command_id = command_id
        self.name = name
        self.frame_type = frame_type
        self.arguments = list(args)
        self.response_command_id = response_command_id

    def __repr__(self):
        """Friendly command string conversion

        Returns:
            str -- Friendly debug representation
        """
        return '<{}("{}", {}, {})>'.format(
            self.__class__.__name__,
            self.name,
            self.command_id,
            self.frame_type.name
        )

    def __str__(self):
        """Return name of the command

        Returns:
            str -- Command name
        """
        return self.name

    def __int__(self):
        """Return command identifier

        Returns:
            int -- Command identifier
        """
        return self.command_id

    def print_definition(self, prefix=''):
        """Prints command definition in YAML format

        Keyword Arguments:
            prefix {str} -- What to prefix every output line with (default: {''})
        """
        print(prefix + '{}:'.format(self.name))
        new_prefix = prefix + '  '

        for attr in ['command_id', 'frame_type']:
            value = self.__getattribute__(attr)

            if value is not None:
                if isinstance(value, type):
                    value = value.__name__

                print(new_prefix + '{}: {}'.format(attr, value))
        print(new_prefix + 'arguments:')
        for argument in self.arguments:
            argument.print_definition(new_prefix + '  ')


DEFAULT_QUERY_COMMAND = Command(0, "queryDev", FrameType.SEND)
