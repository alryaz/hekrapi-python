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
    base_description = "[Account {}]"


# -- Account low level response exceptions
# ---- Request exceptions
class AccountRequestException(AccountException):
    base_description = AccountException.base_description + " [Request]"


class AccountConnectionException(AccountRequestException):
    extended_description = "could not connect (error: {})"


class AccountRequestTimeoutException(AccountRequestException):
    extended_description = "request timed out"


# ---- Response exceptions
class AccountResponseException(AccountException):
    base_description = AccountException.base_description + " [Response]"


class AccountUnknownResponseException(AccountResponseException):
    extended_description = "unknown response (status: {})"


class AccountErrorResponseException(AccountResponseException):
    extended_description = "error response (status: {}, error content: {})"


class AccountJSONInvalidException(AccountUnknownResponseException):
    extended_description = "invalid response (json error: {})"


# -- Account authentication exceptions
class AccountAuthenticationException(HekrAPIException):
    base_description = AccountException.base_description + " [Auth]"


class AccountNotAuthenticatedException(AccountAuthenticationException):
    extended_description = "account not authenticated"


class AccountCredentialsException(AccountAuthenticationException):
    extended_description = "credentials incorrect"


# ---- Refresh token-related exceptions
class RefreshTokenException(AccountAuthenticationException):
    base_description = AccountException.base_description + " [RToken]"


class RefreshTokenExpiredException(RefreshTokenException):
    """Raised when refresh token is explicitly required and is expired"""
    extended_description = "token expired and is impossible to use in authentication"


class RefreshTokenMissingException(RefreshTokenException):
    extended_description = "token missing"


# ---- Access token-related exceptions
class AccessTokenException(AccountAuthenticationException):
    base_description = AccountException.base_description + " [AToken]"


class AccessTokenExpiredException(AccessTokenException):
    """Raised when access token is explicitly required and is expired"""
    extended_description = "token expired and is impossible to use in authentication"


class AccessTokenMissingException(AccessTokenException):
    extended_description = "token missing"


# Connector-related exceptions
class ConnectorException(HekrAPIException):
    base_description = "[Connector {}]"


class ConnectorListenerActive(ConnectorException):
    extended_description = "listener is already running"


class ConnectorDeviceException(ConnectorException):
    base_description = ConnectorException.base_description + " [Device]"


class ConnectorDeviceCollisionException(ConnectorException):
    extended_description = "collision on device ID '{}'"


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
    base_description = ConnectorException.base_description + " [Error]"


class ConnectorAuthenticationError(ConnectorError):
    base_description = ConnectorException.base_description + " [Error:Auth]"


class ConnectorNotConnectedException(ConnectorException):
    extended_description = "connector not connected"


class ConnectorNotAuthenticatedException(ConnectorException):
    extended_description = "connector not authenticated"


class ConnectorCouldNotConnectException(ConnectorNotConnectedException):
    extended_description = "could not establish connection, reason: {}"


class ConnectorSendError(ConnectorError):
    extended_description = "could not sent request payload, reason: {}"


class ConnectorClosedError(ConnectorError):
    extended_description = "connector closed, reason: {}"


class ConnectorReadError(ConnectorError):
    extended_description = "could not receive response payload, reason: {}"


# Device-related exceptions
class DeviceException(HekrAPIException):
    base_description = "[Device {}]"


class DeviceProtocolNotSetException(DeviceException):
    """Raised when an operation explicitly requires protocol interaction"""
    extended_description = "protocol not set"


class ConnectorUnexpectedMessageIDException(ConnectorNotConnectedException):
    """Raised when received message identifier is not expected"""
    extended_description = "received message ID {} is different from expected {}"


# -- Device connectors exceptions
class DeviceConnectorsException(DeviceException, ConnectorException):
    base_description = DeviceException.base_description + " [Conn]"


class DeviceConnectorMissingException(DeviceConnectorsException):
    extended_description = "connector {} is absent from device"


class DeviceConnectorsMissingException(DeviceConnectorMissingException):
    """Raised when an operation explicitly requires at least one existing connector"""
    extended_description = "no connectors available on device"


class DeviceCloudConnectorBoundException(DeviceConnectorsException):
    """Raised when an attempt to override an existing cloud connector has been made"""
    extended_description = "cloud connector {} is already bound"


class DeviceDirectConnectorBoundException(DeviceConnectorsException):
    """Raised when an attempt to override an existing direct connector has been made"""
    extended_description = "direct connector {} is already bound"


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
    base_description = "[Protocol {}]"


class ProtocolCommandNotFoundException(ProtocolException):
    extended_description = "command '{}' not found"


# -- Command-related exceptions
class CommandException(ProtocolException):
    base_description = "[Command {}]"


# ---- Command data-related exceptions
class CommandDataException(CommandException, ValueError):
    """Raised when provided command data contains invalid keys and/or values"""
    base_description = CommandException.base_description + " [Data]"


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
    base_description = "[Command UNKNOWN]"


# ---- Raw datagram-specific exceptions
class CommandDataRawException(CommandDataException):
    base_description = CommandException.base_description + " [Raw]"


class CommandDataInvalidPrefixException(CommandDataRawException):
    extended_description = "invalid prefix"


class CommandDataInvalidLengthException(CommandDataRawException):
    extended_description = "length different from expected"


class CommandDataInvalidChecksumException(CommandDataRawException):
    extended_description = "checksum different from expected"


class CommandDataInvalidFrameTypeException(CommandDataRawException):
    extended_description = "frame type different from expected"
