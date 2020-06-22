# -*- coding: utf-8 -*-
"""Basic protocol definition for ELRO Connects"""
from hekrapi.protocol import Protocol, Encoding, Command, Argument
from hekrapi.const import FrameType

__all__ = [
    'PROTOCOL',
    'CMD_EQUIPMENT_ADD',
    'CMD_EQUIPMENT_REMOVE',
    'CMD_EQUIPMENT_CONTROL',
    'CMD_EQUIPMENT_CANCEL_REMOVE',
    'CMD_EQUIPMENT_REPLACE',
    'CMD_EQUIPMENT_RENAME',
    'CMD_SCENE_GROUP_SELECT',
]

CMD_EQUIPMENT_CONTROL = "equipment_control"
CMD_EQUIPMENT_ADD = "equipment_add"
CMD_EQUIPMENT_REPLACE = "equipment_replace"
CMD_EQUIPMENT_REMOVE = "equipment_remove"
CMD_EQUIPMENT_CANCEL_REMOVE = "equipment_cancel_remove"
CMD_EQUIPMENT_RENAME = "equipment_rename"

CMD_SCENE_GROUP_SELECT = "scene_group_select"

ARG_EQUIPMENT_ID = "equipment_id"
ARG_STATE = "state"
ARG_NAME = "name"
ARG_GROUP = "group"

ARGUMENT_EQUIPMENT_ID = Argument(ARG_EQUIPMENT_ID, int, None, "device_ID")
ARGUMENT_SCENE_GROUP = Argument(ARG_GROUP, int, None, "scene_type", value_default=0)

PROTOCOL = Protocol(
    Command(1, FrameType.SEND, CMD_EQUIPMENT_CONTROL, arguments=[
        ARGUMENT_EQUIPMENT_ID,
        Argument(ARG_STATE, str, None, "device_status"),
    ]),
    Command(2, FrameType.SEND, CMD_EQUIPMENT_ADD),
    Command(3, FrameType.SEND, CMD_EQUIPMENT_REPLACE, arguments=[
        ARGUMENT_EQUIPMENT_ID
    ]),
    Command(4, FrameType.SEND, CMD_EQUIPMENT_REMOVE, arguments=[
        ARGUMENT_EQUIPMENT_ID
    ]),
    Command(5, FrameType.SEND, CMD_EQUIPMENT_RENAME, arguments=[
        ARGUMENT_EQUIPMENT_ID,
        Argument(ARG_NAME, str, None, "device_name"),
    ]),
    Command(6, FrameType.SEND, CMD_SCENE_GROUP_SELECT, arguments=[ARGUMENT_SCENE_GROUP]),
    Command(7, FrameType.SEND, CMD_EQUIPMENT_CANCEL_REMOVE),
    Command(8, FrameType.SEND, "add_scene", arguments=[
        ARGUMENT_SCENE_GROUP,

    ]),  # @TODO: finish this command
    Command(9, FrameType.SEND, "modify_scene"),  # @TODO: finish this command
    Command(10, FrameType.SEND, "delete_scene"),  # @TODO: finish this command
    # commands 11-13 ?
    Command(14, FrameType.SEND, "get_device_name"),  # @TODO: finish this command
    Command(15, FrameType.SEND, "get_all_equipment_status"),  # @TODO: finish this command
    # command 16 ?
    # command 17 ?
    Command(18, FrameType.SEND, "get_all_scene_info"),  # @TODO: finish this command
    Command(19, FrameType.RECEIVE, "device_status_update"),  # @TODO: finish this command
    Command(21, FrameType.SEND, "time_check"),  # @TODO: finish this command
    Command(23, FrameType.SEND, "add_scene_group"),  # @TODO: finish this command
    Command(24, FrameType.SEND, "modify_scene_group"),  # @TODO: finish this command
    Command(25, FrameType.RECEIVE, "device_alarm_trigger"),  # @TODO: finish this command
    Command(26, FrameType.RECEIVE, "scene_status_update"),  # @TODO: finish this command
    # command 27 ?
    # command 28 ?
    Command(29, FrameType.SEND, "sync_device_status"),  # @TODO: finish this command
    Command(30, FrameType.SEND, "sync_device_name"),  # @TODO: finish this command
    Command(31, FrameType.SEND, "sync_scene"),  # @TODO: finish this command
    Command(32, FrameType.SEND, "scene_handle"),  # @TODO: finish this command
    Command(33, FrameType.SEND, "scene_group_delete"),  # @TODO: finish this command
    Command(34, FrameType.SEND, "model_switch_timer"),  # @TODO: finish this command
    Command(35, FrameType.SEND, "model_timer_syn"),  # @TODO: finish this command
    Command(36, FrameType.SEND, "upload_model_timer"),  # @TODO: finish this command
    Command(37, FrameType.SEND, "model_timer_del"),  # @TODO: finish this command
    # commands 38-100 ?


    # commands 107-250 ?
    Command(251, FrameType.SEND, "send_timezone"),  # @TODO: finish this command
    # commands 252-255 ?
    default_encoding_type=Encoding.JSON
)
