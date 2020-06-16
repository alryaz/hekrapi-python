# -*- coding: utf-8 -*-
"""Account class module for HekrAPI"""
__all__ = [
    'Account',
]
import logging
import asyncio
from json import JSONDecodeError, loads
from typing import Dict, Optional, Tuple, NoReturn, List, Iterable
from datetime import datetime, timedelta

from aiohttp import ClientSession
from hekrapi import Protocol

from .const import DEFAULT_APPLICATION_ID, DEFAULT_APPLICATION_NAME, DEFAULT_APPLICATION_VERSION, \
    DEFAULT_APPLICATION_TYPE, DEFAULT_OS_VERSION, DEFAULT_TIMEOUT
from .device import Device, CloudConnector
from .exceptions import AccountUnauthenticatedException, AccountDevicesUpdateFailedException, \
    HekrAPIException, HekrValueError, AuthenticationFailedException, HekrTypeError, HekrResponseStatusError, \
    RefreshTokenExpiredException, AccessTokenExpiredException

_LOGGER = logging.getLogger(__name__)


class Account:
    """Account class for HekrAPI

    Raises:
        ValueError: Account constructor is not provided possible ways to authenticate
        AccountUnauthenticatedException: Account did not authenticate prior to calling method

    Attributes:
        __username (str): Account username
        __password (str, optional): Account password (not required with token)
        __access_token (str, optional): Authentication 'Bearer' token (not required with password)
        __refresh_token (str, optional): Refresh token (not required with password)
        __devices (dict): Dictionary with 'Device' objects belonging to account
        application_id (str): Application ID (has default value)
    """

    BASE_URL = 'https://user-openapi.hekreu.me'
    BASE_AUTH_URL = 'https://uaa-openapi.hekr.me'

    def __init__(self, username: Optional[str] = None, password: Optional[str] = None,
                 access_token: Optional[str] = None, refresh_token: Optional[str] = None,
                 application_id: str = DEFAULT_APPLICATION_ID, application_name: str = DEFAULT_APPLICATION_NAME,
                 application_version: str = DEFAULT_APPLICATION_VERSION,
                 application_type: str = DEFAULT_APPLICATION_TYPE, os_version: str = DEFAULT_OS_VERSION,
                 reauthenticate_on_fail: bool = True):

        if not access_token and not (username and password):
            raise HekrAPIException("At least one authentication method (token, username/password) must be set up")

        self.application_id = application_id
        self.application_name = application_name
        self.application_version = application_version
        self.application_type = application_type
        self.os_version = os_version

        self.__username = username
        self.__password = password
        self.__access_token = access_token
        self.__refresh_token = refresh_token

        self._access_token_expires_at = None
        self._refresh_token_expires_at = None
        self._user_id = None

        self.reauthenticate_on_fail = reauthenticate_on_fail

        self.__connectors: Dict[Tuple[str, int], CloudConnector] = {}

        self.__devices: Dict[str, Device] = {}

    def get_connector(self, connect_host: str, connect_port: int = 186):
        if not self.__access_token:
            raise AccountUnauthenticatedException(account=self)

        key = (connect_host, connect_port)
        if key not in self.__connectors:
            connector = CloudConnector(
                token=self.__access_token,
                connect_host=connect_host,
                connect_port=connect_port,
                application_id=self.application_id
            )
            self.__connectors[key] = connector
            return connector
        return self.__connectors[key]

    @staticmethod
    def current_time() -> datetime:
        """
        Returns current time.
        Useful to override when offsets are non-UTC.
        :return:
        """
        return datetime.utcnow()

    @property
    def access_token_expires_at(self) -> Optional[datetime]:
        """
        Time and date when the set access token expires.
        By default expiry is scheduled 24 hours since update.
        :return:
        """
        return self._access_token_expires_at

    @property
    def refresh_token_expires_at(self) -> Optional[datetime]:
        """
        Time and date when the set refresh token expires.
        By default expiry is scheduled 30 days since update.
        :return:
        """
        return self._refresh_token_expires_at

    @property
    def access_token_remaining_time(self) -> timedelta:
        """
        Calculate remaining time until access token expires.
        :return: Zero seconds delta (threshold has passed)
        """
        if self._access_token_expires_at is None:
            raise HekrAPIException('Cannot calculate remaining time for access token that is set manually.')

        zero_time = timedelta(seconds=0)
        remaining_time = self.access_token_expires_at - self.current_time()
        return remaining_time if remaining_time > zero_time else zero_time

    @property
    def refresh_token_remaining_time(self) -> timedelta:
        """
        Calculate remaining time until refresh token expires.
        Will return time delta of zero seconds if the threshold has passed.
        :return:
        """
        if self._access_token_expires_at is None:
            raise HekrAPIException('Cannot calculate remaining time for refresh token that is set manually.')

        zero_time = timedelta(seconds=0)
        remaining_time = self.access_token_expires_at - self.current_time()
        return remaining_time if remaining_time > zero_time else zero_time

    @property
    def connectors(self) -> Dict[Tuple[str, int], CloudConnector]:
        """
        Connectors accessor.
        :return: (Host, Port) -> Cloud connector
        """
        return self.__connectors

    @property
    def devices(self) -> Dict[str, Device]:
        """
        Devices accessor.
        :return: Device ID -> Device object
        """
        return self.__devices

    def _generate_auth_header(self):
        """
        Generate authentication header for HTTP requests.
        :raises AccountUnauthenticatedException: When access token is not set
        :raises AccessTokenExpiredException: When access token is considered expired
        :return:
        """
        if not self.__access_token:
            raise AccountUnauthenticatedException(account=self)
        elif not self.access_token_remaining_time:
            raise AccessTokenExpiredException(account=self)

        return {'Authorization': 'Bearer ' + self.__access_token}

    @classmethod
    async def _do_request(cls, url: str, headers: Optional[Dict[str, str]] = None,
                          account: Optional['Account'] = None, **request_args):
        """
        Perform request to HTTP API.
        :param url: URL to request
        :param headers: Headers to pass (will be merged with auth headers if `authenticated=True`)
        :param account: Account to use for authentication
        :param request_args: Additional arguments to pass to requester
        :return:
        """
        if headers is None:
            headers = None if account is None else account._generate_auth_header()
        else:
            raise HekrValueError('headers', expected=('headers dict', None), got=headers)

        async with ClientSession() as session:
            _LOGGER.debug('Sending request payload to %s' % url)
            async with session.post(url, headers=headers, **request_args) as response:
                content = await response.read()
                _LOGGER.debug('Received response (%d): %s' % (response.status, content))

                if response.status == 403:
                    raise AccountUnauthenticatedException(account=account)
                elif response.status != 200:
                    raise HekrResponseStatusError(url, got=response.status, expected=200)

                if 'json' in request_args or response.content_type == 'application/json':
                    return loads(content)
                return content

    @classmethod
    async def refresh_authentication_token(cls, refresh_token: str, expires_in: int = 86400):
        payload = {
            'refresh_token': refresh_token,
            'expires_in': expires_in,
        }
        return await cls._do_request(cls.BASE_AUTH_URL + '/token/refresh', json=payload)

    def _process_auth_response(self, response: Dict) -> NoReturn:
        if not response:
            raise HekrValueError('response', expected='filled response dictionary', got=response)

        if self.__refresh_token != response['refresh_token']:
            self._refresh_token_expires_at = self.current_time() + timedelta(days=30)

        self.__refresh_token = response['refresh_token']
        self.__access_token = response['access_token']
        self._user_id = response['user']
        self._access_token_expires_at = self.current_time() + timedelta(seconds=response['expires_in'])

    async def refresh_authentication(self, expires_in: int = 86400) -> NoReturn:
        """ Refresh authentication manually. """
        if self.__refresh_token is None:
            raise HekrValueError('refresh_token', 'None', 'refresh token')

        if self._refresh_token_expires_at < datetime.now():
            raise RefreshTokenExpiredException()

        response = await self.refresh_authentication_token(self.__refresh_token, expires_in=expires_in)
        _LOGGER.info('Successful token refresh for account %s' % self)
        self._process_auth_response(response)

        await self.update_connectors()

    async def authenticate(self, pid: str = '00000000000', client_type: str = 'ANDROID',
                           attempt_refresh: bool = True) -> NoReturn:
        """Authenticate account with Hekr"""
        if attempt_refresh and self.__refresh_token:
            if datetime.now() < self._refresh_token_expires_at:
                try:
                    await self.refresh_authentication()
                    return
                except AuthenticationFailedException:
                    _LOGGER.warning('Failed to refresh token on account %s, commencing re-login' % self)

        payload = {
            'username': self.__username,
            'password': self.__password,
            'pid': pid,
            'clientType': client_type,
            'appLoginInfo': {
                "id": self.application_id,
                "os": self.os_version,
                "type": self.application_type,
                "appVersion": self.application_version,
                "name": self.application_name,
            }
        }
        try:
            response = await self._do_request(self.BASE_AUTH_URL + '/login', json=payload)
            _LOGGER.info('Successful login for account %s' % self)
            self._process_auth_response(response)

            await self.update_connectors()
        except HekrAPIException:
            raise AuthenticationFailedException(account=self)

    async def get_devices(self) -> Dict[str, dict]:
        auth_header = self._generate_auth_header()
        base_url_devices = self.BASE_URL + '/devices?size={}&page={}'

        request_devices = 20
        current_page = 0

        devices_info = dict()
        async with ClientSession() as session:
            more_devices = True
            while more_devices:
                request_url = base_url_devices.format(
                    request_devices,
                    current_page
                )

                async with session.get(request_url, headers=auth_header) as response:
                    content = await response.read()
                    _LOGGER.debug('Received response (%d) for account %s: %s' % (response.status, self, content))

                    if response.status != 200:
                        await session.close()
                        reason = 'Account credentials incorrect' if response.status in (401, 403) \
                            else 'Unknown HTTP error'
                        raise AccountDevicesUpdateFailedException(account=self, response=response, reason=reason)

                    try:
                        response_list = loads(content)
                    except JSONDecodeError:
                        raise AccountDevicesUpdateFailedException(account=self,
                                                                  response=response,
                                                                  reason='Received non-JSON response')

                    more_devices = (len(response_list) == request_devices)

                    devices_info.update({
                        device_info['devTid']: device_info
                        for device_info in response_list
                    })

        return devices_info

    async def update_connectors(self, graceful: bool = True):
        if graceful:
            tasks = [
                connector.update_token_gracefully(self.__access_token)
                for connector in self.__connectors.values()
            ]
            if tasks:
                await asyncio.wait(tasks)

        else:
            for connector in self.__connectors.values():
                connector.update_token(self.__access_token)

    async def update_devices(self, devices_info: Optional[Dict[str, dict]] = None,
                             protocols: Optional[Iterable['Protocol']] = None,
                             update_existing_device_protocols: bool = False,
                             with_timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Device]:
        """
        Get devices, and update attributes if an object already exists, or create new ones based on retrieved info.
        :param devices_info: Information about devices (via `get_devices`)
        :param protocols: Use specified protocols for detection
        :param update_existing_device_protocols: Update protocols for existing devices
        :param with_timeout: (Optional) Pre-apply timeout on all new and bound devices; will overwrite timeout for
                             devices using same connector to communicate with cloud on every run
        :return: Dictionary with new devices indexed by device ID
        """
        if devices_info is None:
            devices_info = await self.get_devices()

        use_protocol_detection = bool(protocols)

        devices = {}
        for device_id, device_attributes in devices_info.items():
            detect_protocols = use_protocol_detection
            if device_id in self.__devices:
                device = self.__devices[device_id]
                if update_existing_device_protocols:
                    detect_protocols = False
            else:
                device = Device(device_id=device_id, control_key=device_attributes['ctrlKey'])
                device.connector = self.get_connector(connect_host=device_attributes['dcInfo']['connectHost'])
                device.account = self

            device.device_info = device_attributes
            device.connector.timeout = with_timeout

            if detect_protocols:
                for protocol in protocols:
                    if protocol.compatibility_checker(device):
                        device.protocol = protocol
                        break
                # @TODO: probably raise exception for missing detections

        if devices:
            _LOGGER.debug('Devices found for account %s, total device count: %d' % (self, len(self.devices)))
        else:
            _LOGGER.debug('No devices found for account %s' % self)

        return devices
