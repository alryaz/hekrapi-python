# -*- coding: utf-8 -*-
"""Basic protocol definition for ELRO Connects (devices with newer firmware version)"""
from hekrapi.protocol import Command, Argument
from hekrapi.protocols.elro_connects import (
    PROTOCOL as ORIGINAL_PROTOCOL,
    CMD_EQUIPMENT_CONTROL,
    CMD_EQUIPMENT_ADD,
    CMD_EQUIPMENT_REMOVE
)
from hekrapi.const import FrameType


def convert_new_input(value: int) -> int:
    """
    Forward conversion for newer device protocols.
    :param value: Input value (passed to argument)
    :return:
    """
    return (((int(value) ^ -1) + 65536) ^ 291) ^ 4660


def convert_new_output(value: int) -> int:
    """
    Backwards conversion for newer device protocols.
    :param value: Output value (obtained from device)
    :return:
    """
    return -1 ^ ((291 ^ (4660 ^ int(value))) - 65536)


CONVERT_TO_NEW_VERSION = (convert_new_input, convert_new_output)

ARGUMENT_NEW_EQUIPMENT_ID = Argument("equipment_id", CONVERT_TO_NEW_VERSION, None, "device_ID")

PROTOCOL = ORIGINAL_PROTOCOL.extend(
    Command(101, FrameType.SEND, CMD_EQUIPMENT_CONTROL, arguments=[
        ARGUMENT_NEW_EQUIPMENT_ID,
        Argument("state", str, None, "device_status"),
    ]),
    # command 102 ?
    Command(103, FrameType.SEND, "replace_equipment", arguments=[ARGUMENT_NEW_EQUIPMENT_ID]),
    Command(104, FrameType.SEND, "equipment_delete", arguments=[ARGUMENT_NEW_EQUIPMENT_ID]),
    Command(105, FrameType.SEND, "equipment_rename", arguments=[
        ARGUMENT_NEW_EQUIPMENT_ID,
        Argument("name", str, None, "device_name"),
    ]),
    Command(106, FrameType.SEND, "choose_scene_group", arguments=[
        Argument("group", CONVERT_TO_NEW_VERSION, None, "scene_type"),
    ]),
    Command(110, FrameType.SEND, "delete_scene", arguments=[
        Argument("group", int, None, "scene_type", value_default=0),
        Argument("scene_id", CONVERT_TO_NEW_VERSION, None, "scene_ID"),
    ])
)