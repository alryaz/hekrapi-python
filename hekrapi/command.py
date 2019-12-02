# -*- coding: utf-8 -*-
"""Command class module for HekrAPI"""

from enum import IntEnum, Enum
from typing import Union

from .argument import Argument
from .exceptions import HekrTypeError, HekrValueError

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
                 frame_type: FrameType=FrameType.SEND,
                 name: str=None,
                 arguments:list=None,
                 response_command_id:int=None):
        """Command class constructor

        Arguments:
            command_id {int} -- Command identifier for datagrams
            name {str} -- Command name for calls
            frame_type {FrameType} -- Command frame type (per Hekr docs)
        """

        if isinstance(frame_type, str):
            try:
                frame_type = FrameType[frame_type.upper()]
            except KeyError:
                raise ValueError('`frame_type` must be one of the following values (case-insensitive) when passed as string: %s (got %s)' % (', '.join(['`'+value.name.lower()+'`' for value in FrameType]), '`'+frame_type+'`'))

        # circular checking prevents following private attributes
        # from being created automatically
        self.__response_command_id = None
        self.__frame_type = None

        self.command_id = command_id
        self.name = name
        self.response_command_id = response_command_id
        self.frame_type = frame_type
        self.arguments = arguments

    def __repr__(self) -> str:
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

    def __str__(self) -> str:
        """Return name of the command

        Returns:
            str -- Command name
        """
        return self.name

    def __int__(self) -> int:
        """Return command identifier

        Returns:
            int -- Command identifier
        """
        return self.command_id

    @property
    def command_id(self) -> int:
        """Getter for numeric command identifier"""
        return self.__command_id

    @command_id.setter
    def command_id(self, value:int):
        """Setter for numeric command identifier

        Checks whether `command_id` being set to a correct integer value
        between 0 and 255 (a boundary imposed by datagram protocol)

        Arguments:
            value {int} -- Numeric command identifier for given command

        Raises:
            HekrTypeError: Raised when the value fed is not an integer.
            HekrValueError: Raised when a value is out of bounds of bytes constraint.
        """
        if not isinstance(value, int):
            raise HekrTypeError(variable='command_id', expected=int, got=type(value))
        elif 255 < value < 0:
            raise HekrValueError(variable='command_id', expected='integer from 0 to 255', got=value)
        self.__command_id = value

    @property
    def frame_type(self) -> FrameType:
        """Getter for `frame_type` attribute"""
        return self.__frame_type

    @frame_type.setter
    def frame_type(self, value:FrameType):
        """Setter for `frame_type` attribute

        Coerces any incoming value on invocation to `FrameType` class instances.
        Throws exceptions when incorrect data is being fed.

        Arguments:
            value {Any} -- Value (coercible to `FrameType`)

        Raises:
            HekrTypeError: Raised when the value is not coercible to a `FrameType` instance
            HekrValueError: Raised when the value is not `FrameType.SEND` when `response_command_id` attribute is set.
        """
        try:
            if value is None:
                new_frame_type = FrameType.SEND
            elif isinstance(value, str):
                new_frame_type = FrameType[value.upper()]
            else:
                new_frame_type = FrameType(value)
        except KeyError:
            raise HekrValueError(variable='frame_type', expected=', '.join(map(lambda x: "'"+x.name.lower()+"'", FrameType))+" (case-insensitive)", got="'"+value+"'")
        except ValueError:
            raise HekrTypeError(variable='frame_type', expected='coercible to `%s`' % FrameType.__name__, got=type(value))

        if new_frame_type != FrameType.SEND and self.response_command_id is not None:
            raise HekrValueError(variable='frame_type', expected='`%s` due to `response_command_id` being set' % FrameType.SEND, got=new_frame_type)

        self.__frame_type = new_frame_type

    @property
    def arguments(self) -> list:
        return self.__arguments

    @arguments.setter
    def arguments(self, value):
        if isinstance(value, list):
            invalid_types = [type(x) for x in value
                if not isinstance(x, Argument)]

            if invalid_types:
                raise HekrTypeError(variable='arguments list', expected=Argument, got=invalid_types)
        elif value is not None:
            raise HekrTypeError(variable='arguments list', expected=[list, type(None)], got=type(value))

        self.__arguments = value or []

    @property
    def response_command_id(self):
        return self.__response_command_id

    @response_command_id.setter
    def response_command_id(self, value):
        if value is not None:
            if self.frame_type is not None and self.frame_type != FrameType.SEND:
                raise HekrValueError(variable='response_command_id', expected='`None` due to `frame_type` not being set to `FrameType.SEND` (current value `%s`)' % self.frame_type, got=value)
            elif not isinstance(value, int):
                raise HekrTypeError(variable='response_command_id', expected=int, got=type(value))
            elif value < 0:
                raise HekrValueError(variable='response_command_id', expected='>= 0', got=value)
        self.__response_command_id = value