from enum import IntEnum

from .argument import Argument


class FrameType(IntEnum):
    RECEIVE = 0x01
    SEND = 0x02
    DEVICE = 0xFE
    ERROR = 0xFF


class Command(object):
    def __init__(
        self,
        command_id, name, frame_type: FrameType,
        *args: Argument
    ):
        self.command_id = command_id
        self.name = name
        self.frame_type = frame_type
        self.arguments = list(args)

    def __repr__(self):
        return '<{}("{}", {}, {})>'.format(
            self.__class__.__name__,
            self.name,
            self.command_id,
            self.frame_type.name
        )

    def __str__(self):
        return self.name

    def __int__(self):
        self.command_id

    def print_definition(self, prefix=''):
        print(prefix + '{}:'.format(self.name))
        new_prefix = prefix + '  '

        for attr in ['command_id', 'frame_type']:
            value = self.__getattribute__(attr)

            if value is not None:
                if isinstance(value, type):
                    value = value.__name__

                print(new_prefix + '{}: {}'.format(attr, value))
        print(new_prefix + 'arguments:')
        for argument in self.arguments:
            argument.print_definition(new_prefix + '  ')


DEFAULT_QUERY_COMMAND = Command(0, "queryDev", FrameType.SEND)
