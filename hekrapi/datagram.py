# -*- coding: utf-8 -*-
"""Datagram encoding/decoding module for HekrAPI"""

from typing import Union, Tuple

from .exceptions import (
    InvalidMessagePrefixException,
    InvalidMessageLengthException,
    InvalidMessageChecksumException,
    InvalidMessageFrameTypeException,
    InvalidDataMissingKeyException
)
from .const import FRAME_START_IDENTIFICATION

def decode(protocol: 'Protocol', raw: Union[bytearray, str],
           use_variable_names=False,
           filter_values=True
           ) -> Tuple['Command', dict, int]:
    """Decode raw Hekr datagram

    Arguments:
        protocol {[type]} -- [description]
        raw {Union[bytearray, str]} -- [description]

    Keyword Arguments:
        use_variable_names {bool} -- Use variable names when decoding (default: {False})
        filter_values {bool} -- Apply multiplication and typecasting to values (default: {True})

    Raises:
        TypeError: Invalid type provided as function argument
        InvalidMessagePrefixException: Datagram prefix does not match expected
        InvalidMessageLengthException: Datagram length does not match expected
        InvalidMessageChecksumException: Datagram checksum does not match expected
        InvalidMessageFrameTypeException: Datagram frame type does not match expected

    Returns:
        dict -- Dictionary of decoded values
    """
    if isinstance(raw, str):
        decoded = bytearray.fromhex(raw)
    elif isinstance(raw, bytearray):
        decoded = raw
    else:
        raise TypeError(type(raw))

    if decoded[0] != FRAME_START_IDENTIFICATION:
        raise InvalidMessagePrefixException(raw)

    frame_length = decoded[1]
    if frame_length != len(decoded):
        raise InvalidMessageLengthException(raw)

    checksum = decoded[-1]
    current_checksum = sum(decoded[:-1]) % 0x100
    if checksum != current_checksum:
        raise InvalidMessageChecksumException(raw)

    frame_type = decoded[2]
    command_id = decoded[4]
    command = protocol.get_command_by_id(command_id)
    if frame_type != command.frame_type:
        raise InvalidMessageFrameTypeException(raw)

    frame_number = decoded[3]

    current_pos = 5
    data = {}
    for argument in command.arguments:
        next_pos = current_pos + argument.byte_length
        value_output = int.from_bytes(
            decoded[current_pos:next_pos], byteorder='big', signed=False)

        if filter_values:
            if argument.multiplier is not None:
                value_output *= argument.multiplier
                if argument.decimals is not None:
                    value_output = round(value_output, argument.decimals)

            value_output = argument.type_output(value_output)

        data[argument.variable if use_variable_names else argument.name] = value_output
        current_pos = next_pos

    return (command, data, frame_number)

def encode(command: 'Command', data: dict = None, frame_number: int = 1,
           use_variable_names=False, filter_values=True) -> str:
    """Encode raw Hekr datagram

    Arguments:
        command {[type]} -- Command to use arguments from

    Keyword Arguments:
        data {dict} -- Dictionary of decoded values (default: {None})
        frame_number {int} -- Datagram frame number (default: {1})
        use_variable_names {bool} -- Use variable names when encoding (default: {False})
        filter_values {bool} -- Apply multiplication and typecasting (default: {True})

    Raises:
        InvalidDataMissingKeyException: [description]

    Returns:
        str -- [description]
    """
    if data is None:
        data = {}

    raw = bytearray()
    raw.append(FRAME_START_IDENTIFICATION)
    raw.append(command.frame_type)
    raw.append(frame_number)
    raw.append(command.command_id)

    for argument in command.arguments:
        key = argument.variable if use_variable_names else argument.name
        value_input = data.get(key, None)

        if value_input is None:
            raise InvalidDataMissingKeyException(data_key=key)

        if filter_values:
            if argument.multiplier:
                value_input /= argument.multiplier

            value_input = round(value_input)

        # @TODO: make better performing solution
        result = value_input.to_bytes(
            argument.byte_length,
            byteorder='big',
            signed=False)
        raw.extend(result)

    raw.insert(1, len(raw) + 2)
    raw.append(sum(raw) % 0x100)

    return raw.hex().upper()
