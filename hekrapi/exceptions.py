class HekrAPIException(Exception):
    default_reason = 'HekrAPI Exception occured'

    def __init__(self, *args, **kwargs):
        self.arguments = list(args)
        arguments_text = ', '.join([str(a) for a in self.arguments])
        kwargs['reason'] = kwargs.get('reason') or self.default_reason
        super().__init__(
            kwargs['reason'].format(
                **kwargs) + ' (' + arguments_text + ')')


class InvalidMessageException(HekrAPIException):
    default_reason = 'Invalid Hekr message prvided'


class InvalidMessagePrefixException(InvalidMessageException):
    default_reason = 'Message prefix is not standard'


class InvalidMessageLengthException(InvalidMessageException):
    default_reason = 'Message length does not match expected'


class InvalidMessageChecksumException(InvalidMessageException):
    default_reason = 'Message checksum does not match expected'


class InvalidMessageFrameTypeException(InvalidMessageException):
    default_reason = 'Frame type does not match expected'


class InvalidDataException(HekrAPIException):
    default_reason = 'Invalid Hekr data dictionary provided'


class InvalidDataMissingKeyException(InvalidMessageException):
    default_reason = 'Key "{data_key}" not found in provided data dictionary'


class CommandNotFoundException(HekrAPIException):
    default_reason = 'Could not find command'


class CommandFailedException(HekrAPIException):
    default_reason = "Could not execute command '{command}' on '{device.id}', response: {response}"


class HeartbeatFailedException(HekrAPIException):
    default_reason = "Could not execute heartbeat on '{device.id}', response: {response}"


class AuthenticationFailedException(HekrAPIException):
    default_reason = "Authentication failed"


class LocalAuthenticationFailedException(AuthenticationFailedException):
    default_reason = "Local authentication failed"


class CloudAuthenticationFailedException(AuthenticationFailedException):
    default_reason = "Cloud authentication failed"


class AccountUnauthenticatedException(HekrAPIException):
    default_reason = 'Account unauthenticated'


class DeviceProtocolNotSetException(HekrAPIException):
    default_reason = "Device does not have a protocol set"
