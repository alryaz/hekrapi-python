# -*- coding: utf-8 -*-
"""Command class module for HekrAPI"""

from typing import List

from .argument import Argument
from .const import FrameType
from .exceptions import HekrTypeError, HekrValueError, InvalidDataMissingKeyException, \
    InvalidDataGreaterThanException, InvalidDataLessThanException
from .types import CommandData


class Command:
    """Command class for HekrAPI"""

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
        :param invoke_command_id: Command ID to expect invokation from.
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
        Get pythonic command object representation.

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
            invalid_types = [type(x) for x in value
                if not isinstance(x, Argument)]

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

    def encode(self, data: dict, use_variable_names: bool = False, filter_values: bool = True) -> bytes:
        """Encode arguments into an array of bytes."""
        result = bytes()
        for argument in self.arguments:
            key = argument.variable if use_variable_names else argument.name
            value_input = data.get(key, None)

            if value_input is None:
                raise InvalidDataMissingKeyException(data_key=key)

            if argument.value_min is not None and argument.value_min > value_input:
                raise InvalidDataLessThanException(
                    data_key=key,
                    value=value_input,
                    value_min=argument.value_min)

            if argument.value_max is not None and argument.value_max < value_input:
                raise InvalidDataGreaterThanException(
                    data_key=key,
                    value=value_input,
                    value_max=argument.value_max)

            if filter_values:
                if argument.multiplier:
                    value_input /= argument.multiplier

                value_input = argument.type_input(value_input)

            # @TODO: make better performing solution
            result += value_input.to_bytes(
                argument.byte_length,
                byteorder='big',
                signed=False)

        return result

    def decode(self, data: bytes, use_variable_names: bool = False, filter_values: bool = True,
               ignore_extra: bool = False) -> CommandData:
        """Decode passed data"""
        result = {}
        current_pos = 0
        data_length = len(data)
        for argument in self.arguments:
            key = argument.variable if use_variable_names else argument.name

            next_pos = current_pos + argument.byte_length
            if next_pos > data_length:
                raise InvalidDataMissingKeyException(data_key=key)

            value_output = int.from_bytes(data[current_pos:next_pos], byteorder='big', signed=False)

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
            raise Exception('Provided data is longer than expected for command.')

        return result
