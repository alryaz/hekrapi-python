# -*- coding: utf-8 -*-
"""Exception classes for Hekr API"""

class HekrAPIException(Exception):
    """Base exception class for all HekrAPI exceptions"""
    default_reason = 'HekrAPI Exception occured'

    def __init__(self, *args, **kwargs):
        self.arguments = list(args)
        arguments_text = ', '.join([str(a) for a in self.arguments])
        kwargs['reason'] = kwargs.get('reason') or self.default_reason
        super().__init__(
            kwargs['reason'].format(
                **kwargs) + ' (' + arguments_text + ')')


class InvalidMessageException(HekrAPIException):
    """Base exception class for other message-related exceptions"""
    default_reason = 'Invalid Hekr message prvided'


class InvalidMessagePrefixException(InvalidMessageException):
    """Raised when the first character within the datagram does not equate 0x48"""
    default_reason = 'Message prefix is not standard'


class InvalidMessageLengthException(InvalidMessageException):
    """Raised when datagram data length does not equate one provided by the datagram"""
    default_reason = 'Message length does not match expected'


class InvalidMessageChecksumException(InvalidMessageException):
    """Raised when the calculated checksum does not equate one provided by the datagram"""
    default_reason = 'Message checksum does not match expected'


class InvalidMessageFrameTypeException(InvalidMessageException):
    """Raised when deduced command object frame type does not equate one provided by the datagram"""
    default_reason = 'Frame type does not match expected'


class InvalidDataException(HekrAPIException):
    """Base exception class for other data-related exceptions"""
    default_reason = 'Invalid Hekr data dictionary provided'


class InvalidDataMissingKeyException(InvalidDataException):
    """Raised when a specific data key is missing from the provided data dictionary"""
    default_reason = 'Key "{data_key}" not found in provided data dictionary'


class CommandNotFoundException(HekrAPIException):
    """Raised when a command was not found by value"""
    default_reason = 'Could not find command'


class CommandFailedException(HekrAPIException):
    """Raised when command execution response contains an error"""
    default_reason = "Could not execute command '{command}' on '{device.id}', response: {response}"


class HeartbeatFailedException(HekrAPIException):
    """Raised when heartbeat command failed to execute"""
    default_reason = "Could not execute heartbeat on '{device.id}', response: {response}"


class AuthenticationFailedException(HekrAPIException):
    """Base exception class for other authentication-related exceptions"""
    default_reason = "Authentication failed"


class LocalAuthenticationFailedException(AuthenticationFailedException):
    """Raised when local authentication fails"""
    default_reason = "Local authentication failed"


class CloudAuthenticationFailedException(AuthenticationFailedException):
    """Raised when cloud authentication fails"""
    default_reason = "Cloud authentication failed"


class AccountUnauthenticatedException(HekrAPIException):
    """Raised when account is not authenticated during method call that requires authentication"""
    default_reason = 'Account unauthenticated'


class DeviceProtocolNotSetException(HekrAPIException):
    """Raised when device does not have a protocol set after creation"""
    default_reason = "Device does not have a protocol set"


class DeviceConnectionMissingException(HekrAPIException):
    """Raised when device call cannot be made due to missing connection parameters"""
    default_reason = 'Cannot make requests to device until connection parameters are provided'

class AccountDevicesUpdateFailedException(HekrAPIException):
    """Raised when devices update function encounters a status code other than OK"""
    default_reason = 'Update server returned an invalid response code'