"""Exceptions and errors for Hekr API"""


class HekrAPIException(BaseException):
    base_description: str = NotImplemented
    extended_description: str = NotImplemented

    def __str__(self):
        if self.base_description is NotImplemented:
            return BaseException.__str__(self)
        if self.extended_description is NotImplemented:
            return self.base_description.format(*self.args)
        return (self.base_description + ': ' + self.extended_description).format(*self.args)

    def __repr__(self):
        return self.__str__()


# Account-related exception
class AccountException(HekrAPIException):
    base_description = "Exception on account {}"


# -- Account low level response exceptions
class AccountResponseException(AccountException):
    base_description = "Request exception on account {}"


class AccountUnknownResponseException(AccountResponseException):
    extended_description = "unknown response (status: {})"


class AccountErrorResponseException(AccountResponseException):
    extended_description = "error response (status: {}, error content: {})"


class AccountJSONInvalidException(AccountUnknownResponseException):
    extended_description = "invalid response (json error: {})"


# -- Account authentication exceptions
class AccountAuthenticationException(HekrAPIException):
    base_description = "Authentication error on account {}"


class AccountNotAuthenticatedException(AccountAuthenticationException):
    extended_description = "account not authenticated"


class AccountCredentialsException(AccountAuthenticationException):
    extended_description = "credentials incorrect"


# ---- Refresh token-related exceptions
class RefreshTokenException(AccountAuthenticationException):
    base_description = "Refresh token error on account {}"


class RefreshTokenExpiredException(RefreshTokenException):
    """Raised when refresh token is explicitly required and is expired"""
    extended_description = "token expired and is impossible to use in authentication"


class RefreshTokenMissingException(RefreshTokenException):
    extended_description = "token missing"


# ---- Access token-related exceptions
class AccessTokenException(AccountAuthenticationException):
    base_description = "Access token error on account {}"


class AccessTokenExpiredException(AccessTokenException):
    """Raised when access token is explicitly required and is expired"""
    extended_description = "token expired and is impossible to use in authentication"


class AccessTokenMissingException(AccessTokenException):
    extended_description = "token missing"


# Connector-related exceptions
class ConnectorException(HekrAPIException):
    base_description = "Exception on connector {}"


class ConnectorDeviceException(ConnectorException):
    base_description = "Exception on connector {} with device"


class ConnectorDeviceCollisionException(ConnectorException):
    extended_description = "device collision on device ID '{}'"


class ConnectorDeviceNotProvidedException(ConnectorException):
    extended_description = "device ID not found while handling response"


class ConnectorDeviceNotAttachedException(ConnectorException):
    extended_description = "device ID '{}' not attached on connector"


class ConnectorSingleDeviceException(ConnectorException):
    extended_description = "other device '{}' already attached on connector"


class ConnectorTimeoutException(ConnectorException):
    extended_description = "timeout while performing operation '{}'"


class ConnectorOpenAttributeOverrideException(ConnectorException):
    extended_description = "cannot override attribute '{}' on open connector"


class ConnectorError(ConnectorException):
    base_description = "Error on connector {}"


class ConnectorAuthenticationError(ConnectorError):
    base_description = "authentication invalid"


class ConnectorNotConnectedException(ConnectorException):
    extended_description = "connector not connected"


class ConnectorCouldNotConnectException(ConnectorNotConnectedException):
    extended_description = "could not establish connection, reason: {}"


class ConnectorSendError(ConnectorError):
    extended_description = "could not sent request payload, reason: {}"


class ConnectorReadError(ConnectorError):
    extended_description = "could not receive response payload, reason: {}"


# Device-related exceptions
class DeviceException(HekrAPIException):
    base_description = "Exception on device {}"


class DeviceProtocolNotSetException(DeviceException):
    """Raised when an operation explicitly requires protocol interaction"""
    extended_description = "protocol not set"


class ConnectorUnexpectedMessageIDException(ConnectorNotConnectedException):
    """Raised when received message identifier is not expected"""
    extended_description = "received message ID {} is different from expected {}"


# -- Device connectors exceptions
class DeviceConnectorsException(DeviceException, ConnectorException):
    base_description = "Exception with connector(s) on device {}"


class DeviceConnectorMissingException(DeviceConnectorsException):
    extended_description = "connector {} is absent from device"


class DeviceConnectorsMissingException(DeviceConnectorMissingException):
    """Raised when an operation explicitly requires at least one existing connector"""
    extended_description = "no connectors available on device"


class DeviceCloudConnectorBoundException(DeviceConnectorsException):
    """Raised when an attempt to override an existing cloud connector has been made"""
    extended_description = "cloud connector {} is already bound"


class DeviceLocalConnectorBoundException(DeviceConnectorsException):
    """Raised when an attempt to override an existing local connector has been made"""
    extended_description = "local connector {} is already bound"


class DeviceConnectorsFailedException(DeviceConnectorsException):
    """Raised when an attempt to communicate with device over connectors was made, but failed"""
    extended_description = "connectors failed with errors: {}"


class DeviceConnectorNotConnectedException(DeviceConnectorsException, ConnectorNotConnectedException):
    """Raised when an operation explicitly requires an open connector"""
    extended_description = "connector {} is closed"


class DeviceConnectorsNotConnectedException(DeviceConnectorNotConnectedException):
    """Raised when an operation explicitly requires at least one open connector"""
    extended_description = "all available connectors are closed"


# Protocol-related exceptions
class ProtocolException(HekrAPIException):
    base_description = "Error with protocol {}"


# -- Command-related exceptions
class CommandException(ProtocolException):
    base_description = "Error with command {}"


# ---- Command data-related exceptions
class CommandDataException(CommandException, ValueError):
    """Raised when provided command data contains invalid keys and/or values"""
    base_description = "Error with data for command {}"


class CommandDataExtraException(CommandDataException):
    extended_description = "extra fields in provided data: {}"


class CommandDataOutOfBoundsException(CommandDataException):
    """Raised when a value for argument is beyond argument min/max thresholds"""
    extended_description = "value for field {} is out of argument bounds"


class CommandDataLessThanException(CommandDataException):
    """Raised when a value for argument is less than the argument's minimum value"""
    extended_description = "value for field {} is less than {}"


class CommandDataGreaterThanException(CommandDataException):
    """Raised when a value for argument is greater than the argument's maximum value"""
    extended_description = "value for field {} is greater than {}"


# ---- Missing data exceptions
class CommandDataMissingException(CommandDataException):
    extended_description = "missing fields in provided data: {}"


class CommandDataUnknownCommandException(CommandDataMissingException):
    base_description = "Error with data, command unknown"
    extended_description = "missing fields in provided data: {}"


# ---- Raw datagram-specific exceptions
class CommandDataRawException(CommandDataException):
    base_description = "Error with raw datagram for command {}"


class CommandDataInvalidPrefixException(CommandDataRawException):
    extended_description = "invalid prefix"


class CommandDataInvalidLengthException(CommandDataRawException):
    extended_description = "length different from expected"


class CommandDataInvalidChecksumException(CommandDataRawException):
    extended_description = "checksum different from expected"


class CommandDataInvalidFrameTypeException(CommandDataRawException):
    extended_description = "frame type different from expected"
