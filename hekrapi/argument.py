# -*- coding: utf-8 -*-
# pylint: disable=too-many-instance-attributes,too-many-arguments
"""Argument class module for HekrAPI"""

from typing import Callable, Any, Union, Tuple, Optional
from enum import IntEnum

ArgumentType = Callable[[Any], Any]


class Argument:
    """Argument class for HekrAPI"""

    def __init__(self, name: str,
                 value_type: Union[Tuple[ArgumentType, ArgumentType], ArgumentType]=int,
                 byte_length: int=1,
                 variable: Optional[str]=None,
                 multiplier: Optional[Union[int, float]]=None,
                 decimals: Optional[int]=None,
                 value_min: Optional[Union[int, float]]=None,
                 value_max: Optional[Union[int, float]]=None,
                 ):
        """Argument class constructor

        Arguments:
            name {str} -- Argument name

        Keyword Arguments:
            value_type {Union[Tuple[ArgumentType, ArgumentType], ArgumentType]} --
                Input and output type (may be different if defined as tuple) (default: {int})
            byte_length {int} -- Length of input value in bytes (default: {1})
            variable {Optional[str]} -- Variable name (default: argument's name)
            multiplier {Optional[Union[int, float]]} -- What to multiply input/divide output values by
                (default: {None})
            decimals {Optional[int]} -- Decimals to round input value to (in absence
                of explicit setting, extracted from `multiply` attribute) (default: {None})
            value_min {Optional[Union[int, float]]} -- Minimum value during encoding (default: {None})
            value_max {Optional[Union[int, float]]} -- Maximum value during encoding (default: {None})
        """
        self.name = name
        self.variable = variable
        self.byte_length = byte_length

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
        self.decimals = decimals
        self.multiplier = multiplier

    def __repr__(self):
        """Overloaded argument definiton

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