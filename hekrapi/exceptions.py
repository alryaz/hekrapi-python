# -*- coding: utf-8 -*-
"""Exception classes for Hekr API"""


class HekrAPIException(BaseException):
    pass


class HekrAPIFormattedException(HekrAPIException):
    """Base exception class for all HekrAPI exceptions"""
    default_message = 'HekrAPI Exception occured'

    def __init__(self, *args, **kwargs):
        self.arguments = list(args)
        arguments_text = ', '.join([str(a) for a in self.arguments])
        kwargs['reason'] = kwargs.get('reason') or 'unknown'
        # @TODO: remove 'message' key from kwargs
        super().__init__(
            (kwargs.get('message', self.default_message)).format(
                **kwargs) + (' (' + arguments_text + ')' if arguments_text else ''))


class InvalidMessageException(HekrAPIFormattedException):
    """Base exception class for other message-related exceptions"""
    default_message = 'Invalid Hekr message provided'


class InvalidMessagePrefixException(InvalidMessageException):
    """Raised when the first character within the datagram does not equate 0x48"""
    default_message = 'Message prefix is not standard'


class InvalidMessageLengthException(InvalidMessageException):
    """Raised when datagram data length does not equate one provided by the datagram"""
    default_message = 'Message length does not match expected'


class InvalidMessageChecksumException(InvalidMessageException):
    """Raised when the calculated checksum does not equate one provided by the datagram"""
    default_message = 'Message checksum does not match expected'


class InvalidMessageFrameTypeException(InvalidMessageException):
    """Raised when deduced command object frame type does not equate one provided by the datagram"""
    default_message = 'Frame type does not match expected'


class InvalidDataException(HekrAPIFormattedException):
    """Base exception class for other data-related exceptions"""
    default_message = 'Invalid Hekr data dictionary provided'


class InvalidDataMissingKeyException(InvalidDataException):
    """Raised when a specific data key is missing from the provided data dictionary"""
    default_message = "Key `{data_key}` not found in provided data dictionary"


class InvalidDataLessThanException(InvalidDataException):
    default_message = "Key `{data_key}` contains value '{value}' that is less than minimum '{value_min}'"


class InvalidDataGreaterThanException(InvalidDataException):
    default_message = "Key `{data_key}` contains value '{value}' that is greater than maximum '{value_max}'"


class CommandNotFoundException(HekrAPIFormattedException):
    """Raised when a command was not found by value"""
    default_message = 'Could not find command'


class CommandFailedException(HekrAPIFormattedException):
    """Raised when command execution response contains an error"""
    default_message = "Could not execute command '{command}' on '{device.device_id}', reason: {reason}"


class HeartbeatFailedException(HekrAPIFormattedException):
    """Raised when heartbeat command failed to execute"""
    default_message = "Could not execute heartbeat on '{device.device_id}', response: {response}"


class AuthenticationFailedException(HekrAPIFormattedException):
    """Base exception class for other authentication-related exceptions"""
    default_message = "Authentication failed: {reason}"


class AccountUnauthenticatedException(HekrAPIFormattedException):
    """Raised when account is not authenticated during method call that requires authentication"""
    default_message = 'Account unauthenticated'


class DeviceProtocolNotSetException(HekrAPIFormattedException):
    """Raised when device does not have a protocol set after creation"""
    default_message = "Device does not have a protocol set"


class DeviceConnectionMissingException(HekrAPIFormattedException):
    """Raised when device call cannot be made due to missing connection parameters"""
    default_message = 'Cannot make requests to device until connection parameters are provided'


class AccountDevicesUpdateFailedException(HekrAPIFormattedException):
    """Raised when devices update function encounters a status code other than OK"""
    default_message = 'Devices update on account failed, reason: {reason}'


class HekrAPIExpectedGotException(HekrAPIException):
    """Base exception for variable-expected-got exceptions"""
    default_message = "For variable {variable} expected {expected}, got {got}"

    def __init__(self, variable, got, expected):
        if not isinstance(expected, list):
            expected = [expected]

        expected = ', '.join([
            ('`' + v.__name__ + '`' if isinstance(v, type)
            else str(v))
            for v in expected
        ])

        if not isinstance(got, list):
            got = [got]

        got = ', '.join([('`' + v.__name__ + '`' if isinstance(v, type) else str(v)) for v in got])

        variable = str(variable)
        variable = variable if ' ' in variable else '`' + variable + '`'

        super().__init__(self.default_message.format(variable=variable, got=got, expected=expected))


class HekrTypeError(HekrAPIExpectedGotException):
    default_message = 'Type for {variable} is invalid (expected {expected}; got {got})'


class HekrValueError(HekrAPIExpectedGotException):
    default_message = 'Value(s) for {variable} is invalid (expected {expected}; got {got})'
