# -*- coding: utf-8 -*-
"""Account class module for HekrAPI"""
__all__ = [
    'Account',
]
import logging
from json import JSONDecodeError, loads
from typing import Dict, Optional, Tuple, NoReturn
from datetime import datetime, timedelta

from aiohttp import ClientSession

from .const import DEFAULT_APPLICATION_ID
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
                 application_id: str = DEFAULT_APPLICATION_ID, reauth_on_fail: bool = True):
        # @TODO: refactor after enabling authentication support
        if not access_token and not (username and password):
            raise HekrAPIException("At least one authentication method (token, username/password) must be set up")

        self.application_id = application_id

        self.__username = username
        self.__password = password
        self.__access_token = access_token
        self.__refresh_token = refresh_token

        self._access_token_expires_at = None
        self._refresh_token_expires_at = None
        self._user_id = None

        self.reauth_on_fail = reauth_on_fail

        self.__connectors = {}

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

    @property
    def access_token_expires_at(self):
        return self._access_token_expires_at

    @property
    def refresh_token_expires_at(self):
        return self._refresh_token_expires_at

    @property
    def access_token_remaining_time(self) -> timedelta:
        if self._access_token_expires_at is None:
            return timedelta(seconds=-1)
        return self.access_token_expires_at - datetime.now()

    @property
    def connectors(self) -> Dict[Tuple[str, int], CloudConnector]:
        return self.__connectors

    @property
    def devices(self) -> Dict[str, Device]:
        """Device dictionary accessor

        Returns:
            Dict[str, Device] -- dictionary of devices (device_id => Device object)
        """
        return self.__devices

    def _generate_auth_header(self):
        if not self.__access_token:
            raise AccountUnauthenticatedException(account=self)
        elif self._access_token_expires_at < datetime.now():
            raise AccessTokenExpiredException(account=self)

        return {'Authorization': 'Bearer ' + self.__access_token}

    @classmethod
    async def _do_request(cls, url: str, headers: Optional[Dict[str,str]] = None,
                          account: Optional['Account'] = None, authenticated: bool = False,
                          **request_args):
        if headers is None:
            if authenticated:
                if account is None:
                    raise HekrValueError('account', expected='account (authenticated=true)', got=account)
                headers = account._generate_auth_header()
        else:
            raise HekrValueError('headers', expected=('headers dict', None), got=headers)

        async with ClientSession() as session:
            _LOGGER.debug('Sending request payload to %s' % url)
            async with session.post(url, headers=headers, **request_args) as response:
                content = await response.read()
                _LOGGER.debug('Received response (%d): %s' % (response.status, content))

                if response.status == 403:
                    raise AuthenticationFailedException(account=account)
                elif response.status != 200:
                    raise HekrResponseStatusError(url, got=response.status, expected=200)

                if 'json' in request_args or response.content_type == 'application/json':
                    return loads(content)
                return content

    async def _do_account_request(self, url: str, headers: Optional[Dict[str,str]] = None,
                                  authenticated: bool = True, **request_args):
        """ Shortcut method to do account-bound requests. """
        try:
            return await self._do_request(url, headers=headers, account=self,
                                        authenticated=authenticated, **request_args)
        except AuthenticationFailedException as e:
            raise AccountUnauthenticatedException(account=self, **e.arguments)

    @classmethod
    async def refresh_authentication_token(cls, refresh_token: str, expires_in: int = 86400):
        payload = {
            'refresh_token': refresh_token,
            'expires_in': expires_in,
        }
        return await cls._do_request(cls.BASE_AUTH_URL + '/token/refresh', json=payload, authenticated=False)

    def _process_auth_response(self, response: Dict) -> NoReturn:
        if not response:
            raise HekrValueError('response', expected='filled response dictionary', got=response)

        if self.__refresh_token != response['refresh_token']:
            self._refresh_token_expires_at = datetime.now() + timedelta(days=30)

        self.__refresh_token = response['refresh_token']
        self.__access_token = response['access_token']
        self._user_id = response['user']
        self._access_token_expires_at = datetime.now() + timedelta(seconds=response['expires_in'])

    async def refresh_authentication(self, expires_in: int = 86400) -> NoReturn:
        """ Refresh authentication manually. """
        if self.__refresh_token is None:
            raise HekrValueError('refresh_token', 'None', 'refresh token')

        if self._refresh_token_expires_at < datetime.now():
            raise RefreshTokenExpiredException()

        response = await self.refresh_authentication_token(self.__refresh_token, expires_in=expires_in)
        _LOGGER.info('Successful token refresh for account %s' % self)
        self._process_auth_response(response)

    async def authenticate(self, pid: str = '00000000000', client_type: str = 'ANDROID',
                           app_version: str = '1.0.0:0', app_name: str = "hekrapi",
                           attempt_refresh: bool = True) -> NoReturn:
        """Authenticate account with Hekr"""
        if attempt_refresh and self.__refresh_token:
            if datetime.now() < self.expires_at:
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
                "os": 9,
                "type": "hekrapi",
                "appVersion": app_version,
                "name": "hekrapi",
            }
        }
        try:
            response = await self._do_request(
                url=self.BASE_AUTH_URL + '/login',
                authenticated=False,
                json=payload
            )
            _LOGGER.info('Successful login for account %s' % self)
            self._process_auth_response(response)
        except:
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

    async def update_devices(self, devices_info: Optional[Dict[str, dict]] = None) -> Dict[str, Device]:
        """
        Get devices, and update attributes if an object already exists, or create new ones based on retrieved info.
        :return: Dictionary with new devices indexed by device ID
        """

        if devices_info is None:
            devices_info = await self.get_devices()

        devices = {}
        for device_id, device_attributes in devices_info:
            if device_id in self.__devices:
                self.__devices[device_id].device_info = device_attributes
            else:
                device = Device(device_id=device_id, control_key=device_attributes['ctrlKey'])
                device.connector = self.get_connector(connect_host=device_attributes['dcInfo']['connectHost'])

                devices[device_id] = device

        if devices:
            self.__devices.update(devices)

        return devices
