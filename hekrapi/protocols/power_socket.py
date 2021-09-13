# -*- coding: utf-8 -*-
""" Basic protocol definition for a smart power meter """
from enum import IntEnum
from typing import Union, Any

from ..argument import Argument, OptionalArgument
from ..command import Command, FrameType
from ..protocol import DictProtocol, TO_STR, TO_FLOAT, TO_BOOL, TO_SIGNED_FLOAT

__all__ = [
    "PROTOCOL"
]


PROTOCOL = DictProtocol(
    Command(0, FrameType.SEND, "Quary", response_command_id=1),
    Command(1, FrameType.RECEIVE, "Report", arguments=[
        Argument("power", TO_BOOL, 1, "power"),
    ]),
    Command(2, FrameType.SEND, "SetPower", arguments=[
        Argument("power", TO_BOOL, 1, "power"),
    ], response_command_id=1),
    compatibility_checker=lambda d: d.product_name == 'Socket',
    name="Power Socket"
)
