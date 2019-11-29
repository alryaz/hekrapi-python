# -*- coding: utf-8 -*-
"""Argument class module for HekrAPI"""

from enum import IntEnum
from decimal import Decimal


class Argument(object):
    """Argument class for HekrAPI"""
    def __init__(self, name, type, byte_length, variable=None,
                 multiplier=None, decimals=None,
                 min=None, max=None, format=None
                 ):
        self.name = name
        self.variable = variable or name
        self.byte_length = byte_length

        if isinstance(type, IntEnum):
            self.type_input = int
            self.type_output = type

        elif isinstance(type, tuple):
            self.type_input = type[0]
            self.type_output = type[1]

        else:
            self.type_input = type
            self.type_output = type

        self.min = min
        self.max = max
        self.multiplier = multiplier

        # @TODO: check if numeric
        if multiplier is not None and decimals is None:
            self.decimals = str(self.multiplier)[::-1].find('.')
        else:
            self.decimals = decimals

    def __repr__(self):
        return '<{}({})>'.format(self.__class__.__name__, self.name)

    def print_definition(self, prefix=''):
        print(prefix + self.name + ':')
        new_prefix = prefix + '  '

        for attr in ['variable', 'type_input', 'type_output',
                     'multiplier', 'decimals', 'min', 'max']:
            value = self.__getattribute__(attr)

            if value is not None:
                if isinstance(value, type):
                    value = value.__name__

                print(new_prefix + '{}: {}'.format(attr, value))
