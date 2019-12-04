""" Helpers for Hekr API """
from typing import TYPE_CHECKING, Dict, Union, Any, Tuple
from re import sub
from random import getrandbits
from base64 import b64encode

from .const import FRAME_START_IDENTIFICATION
from .exceptions import *

if TYPE_CHECKING:
    from .protocol import Protocol
    from .command import Command


def sensitive_info_filter(content: str) -> str:
    """
    Filters sensitive information from string for logs.

    :param content: Content to filter.
    :type content: str
    :return: Filtered content.
    :rtype: str
    """
    return sub(r'("(ctrlKey|token)"\s*:\s*")[^"]+(")',
               r'\1<redacted>\3',
               content)


def device_id_from_mac_address(mac_address: Union[str, bytearray]) -> str:
    """
    Convert device's physical address to a device ID
    :param mac_address: MAC-address in dash/colon/spaced/concatenated format
    :type mac_address: str, bytes, bytearray
    :return: Device ID
    :rtype: str
    """
    if isinstance(mac_address, (bytes, bytearray)):
        mac_address = mac_address.hex()

    for delimiter in [':', '-', ' ']:
        mac_address = mac_address.replace(delimiter, '')

    mac_address = mac_address.upper()
    return 'ESP_2M_' + mac_address


def generate_ws_key() -> str:
    """
    Generates WebSocket secret key to send as a header with authentication request.
    :return: Unique WebSocket key
    """
    raw_key = bytes(getrandbits(8) for _ in range(16))
    return b64encode(raw_key).decode()


def datagram_decode(protocol: 'Protocol', raw: Union[str, bytes, bytearray],
                    use_variable_names=False,
                    filter_values=True
                    ) -> Tuple['Command', Dict[str, Any], int]:
    """
    Decode raw datagram
    :param protocol: Protocol definition
    :param raw: Raw datagram
    :param use_variable_names: Use variable names as data keys
    :param filter_values: Apply filters to values
    :type: protocol: Protocol
    :type: raw: str, bytes, bytearray
    :type: use_variable_names: bool
    :type: filter_values: bool
    :return: command object, dictionary of values, frame number
    :rtype: (Command, dict[str, Any], int)
    """
    if isinstance(raw, str):
        decoded = bytearray.fromhex(raw)
    elif isinstance(raw, bytes):
        decoded = bytearray(raw)
    elif isinstance(raw, bytearray):
        decoded = raw
    else:
        raise HekrTypeError(variable='raw', expected=[str, bytearray], got=type(raw))

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
    if frame_type != command.frame_type.value:
        raise InvalidMessageFrameTypeException(raw)

    frame_number = decoded[3]

    current_pos = 5
    data = {}
    for argument in command.arguments:
        next_pos = current_pos + argument.byte_length
        value_output = int.from_bytes(decoded[current_pos:next_pos], byteorder='big', signed=False)

        if filter_values:
            if argument.multiplier is not None:
                value_output *= argument.multiplier
                if argument.decimals is not None:
                    value_output = round(value_output, argument.decimals)

            value_output = argument.type_output(value_output)

        data[argument.variable if use_variable_names else argument.name] = value_output
        current_pos = next_pos

    return command, data, frame_number


def datagram_encode(command: 'Command', data: dict = None, frame_number: int = 1,
                    use_variable_names=False, filter_values=True) -> str:
    """
    Encode data into raw datagram
    :param command: Command object
    :param data: Dictionary of values
    :param frame_number: Frame number
    :param use_variable_names: Use variable names as data keys
    :param filter_values: Apply filters to values
    :return: Raw datagram
    :rtype: str
    """
    if data is None:
        data = {}

    raw = bytearray()
    raw.append(FRAME_START_IDENTIFICATION)
    raw.append(command.frame_type.value)
    raw.append(frame_number)
    raw.append(command.command_id)

    for argument in command.arguments:
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
