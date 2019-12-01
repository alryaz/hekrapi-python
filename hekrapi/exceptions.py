# -*- coding: utf-8 -*-
"""Exception classes for Hekr API"""

class HekrAPIException(Exception):
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


class InvalidMessageException(HekrAPIException):
    """Base exception class for other message-related exceptions"""
    default_message = 'Invalid Hekr message prvided'


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


class InvalidDataException(HekrAPIException):
    """Base exception class for other data-related exceptions"""
    default_message = 'Invalid Hekr data dictionary provided'


class InvalidDataMissingKeyException(InvalidDataException):
    """Raised when a specific data key is missing from the provided data dictionary"""
    default_message = 'Key "{data_key}" not found in provided data dictionary'


class CommandNotFoundException(HekrAPIException):
    """Raised when a command was not found by value"""
    default_message = 'Could not find command'


class CommandFailedException(HekrAPIException):
    """Raised when command execution response contains an error"""
    default_message = "Could not execute command '{command}' on '{device.device_id}', reason: {reason}, response: {response}"


class HeartbeatFailedException(HekrAPIException):
    """Raised when heartbeat command failed to execute"""
    default_message = "Could not execute heartbeat on '{device.device_id}', response: {response}"


class AuthenticationFailedException(HekrAPIException):
    """Base exception class for other authentication-related exceptions"""
    default_message = "Authentication failed"


class LocalAuthenticationFailedException(AuthenticationFailedException):
    """Raised when local authentication fails"""
    default_message = "Local authentication failed"


class CloudAuthenticationFailedException(AuthenticationFailedException):
    """Raised when cloud authentication fails"""
    default_message = "Cloud authentication failed"


class AccountUnauthenticatedException(HekrAPIException):
    """Raised when account is not authenticated during method call that requires authentication"""
    default_message = 'Account unauthenticated'


class DeviceProtocolNotSetException(HekrAPIException):
    """Raised when device does not have a protocol set after creation"""
    default_message = "Device does not have a protocol set"


class DeviceConnectionMissingException(HekrAPIException):
    """Raised when device call cannot be made due to missing connection parameters"""
    default_message = 'Cannot make requests to device until connection parameters are provided'

class AccountDevicesUpdateFailedException(HekrAPIException):
    """Raised when devices update function encounters a status code other than OK"""
    default_message = 'Devices update on account failed, reason: {reason}'