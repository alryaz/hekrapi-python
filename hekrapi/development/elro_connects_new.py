# -*- coding: utf-8 -*-
"""Basic protocol definition for ELRO Connects (devices with newer firmware version)"""
from hekrapi.protocol import Command, Argument, register_supported_protocol
from hekrapi.development.elro_connects import ELROConnectsProtocol
from hekrapi.enums import FrameType


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


@register_supported_protocol
class ELROConnectsNewProtocol(ELROConnectsProtocol):
    equipment_control = Command(101, FrameType.SEND, arguments=[
        ARGUMENT_NEW_EQUIPMENT_ID,
        Argument("state", str, None, "device_status"),
    ])
    # command 102 ?
    replace_equipment = Command(103, FrameType.SEND, arguments=[ARGUMENT_NEW_EQUIPMENT_ID])
    equipment_delete = Command(104, FrameType.SEND, arguments=[ARGUMENT_NEW_EQUIPMENT_ID])
    equipment_rename = Command(105, FrameType.SEND, arguments=[
        ARGUMENT_NEW_EQUIPMENT_ID,
        Argument("name", str, None, "device_name"),
    ])
    choose_scene_group = Command(106, FrameType.SEND, arguments=[
        Argument("group", CONVERT_TO_NEW_VERSION, None, "scene_type"),
    ])
    delete_scene = Command(110, FrameType.SEND, arguments=[
        Argument("group", int, None, "scene_type", value_default=0),
        Argument("scene_id", CONVERT_TO_NEW_VERSION, None, "scene_ID"),
    ])
