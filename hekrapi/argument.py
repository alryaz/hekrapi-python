# -*- coding: utf-8 -*-
# pylint: disable=too-many-instance-attributes,too-many-arguments
"""Argument class module for HekrAPI"""

from typing import Callable, Any, Union, Tuple
from enum import IntEnum

ArgumentType = Callable[[Any], Any]
class Argument:
    """Argument class for HekrAPI

    Returns:
        Argument -- Argument definition
    """

    def __init__(self, name: str,
                 value_type: Union[Tuple[ArgumentType, ArgumentType], ArgumentType],
                 byte_length: int,
                 variable: Union[str, type(None)]=None,
                 multiplier: Union[int, float, type(None)]=None,
                 decimals: Union[int, type(None)]=None,
                 value_min: Union[int, float, type(None)]=None,
                 value_max: Union[int, float, type(None)]=None,
                 ):
        """Argument constructor

        Arguments:
            name {str} -- Argument name
            value_type {Union[Tuple[ArgumentType, ArgumentType], ArgumentType]} -- Value type
            byte_length {int} -- Length of input value in bytes

        Keyword Arguments:
            variable {Union[str, type} -- Variable name
                                          (in absence, name argument is used)
                                          (default: {None})
            multiplier {Union[int, float, type} -- What to multiply input/divide output values by
                                                   (default: {None})
            decimals {Union[int, type} -- Decimals to round input value to
                                          (in absence, extracted from multiply argument)
                                          (default: {None})
            value_min {Union[int, float, type} -- [description] (default: {None})
            value_max {Union[int, float, type} -- [description] (default: {None})
        """
        self.name = name
        self.variable = variable or name
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

        self.min = value_min
        self.max = value_max
        self.multiplier = multiplier

        # @TODO: check if numeric
        if multiplier is not None and decimals is None:
            self.decimals = str(self.multiplier)[::-1].find('.')
        else:
            self.decimals = decimals

    def __repr__(self):
        """Overloaded argument definiton

        Returns:
            str -- Human-friendly argument definition
        """
        return '<{}({})>'.format(self.__class__.__name__, self.name)

    def print_definition(self, prefix=''):
        """Print argument definition in YAML format

        Keyword Arguments:
            prefix {str} -- What to prefix every line with (default: {''})
        """
        print(prefix + self.name + ':')
        new_prefix = prefix + '  '

        for attr in ['variable', 'type_input', 'type_output',
                     'multiplier', 'decimals', 'min', 'max']:
            argument_attribute_value = self.__getattribute__(attr)

            if argument_attribute_value is not None:
                if isinstance(argument_attribute_value, type):
                    argument_attribute_value = argument_attribute_value.__name__

                print(new_prefix + '{}: {}'.format(attr, argument_attribute_value))
