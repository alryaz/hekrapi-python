# -*- coding: utf-8 -*-
"""Account class module for HekrAPI"""
__all__ = ['Account']

import logging
from datetime import datetime, timedelta
from functools import partialmethod
from json import JSONDecodeError, loads
from typing import Dict, Optional, Tuple, Iterable, TYPE_CHECKING, List, Union, Any, Sequence, BinaryIO

from .exceptions import AccessTokenMissingException, AccessTokenExpiredException, AccountCredentialsException, \
    AccountUnknownResponseException, AccountJSONInvalidException, AccountErrorResponseException, \
    AccountNotAuthenticatedException

try:
    from typing import NoReturn
except ImportError:
    NoReturn = None

from aiohttp import ClientSession

from .const import DEFAULT_APPLICATION_ID, DEFAULT_APPLICATION_NAME, DEFAULT_APPLICATION_VERSION, \
    DEFAULT_APPLICATION_TYPE, DEFAULT_OS_VERSION, DEFAULT_TIMEOUT
from .device import Device, DeviceInfo, DeviceType
from .types import DeviceID
from .connector import CloudConnector

if TYPE_CHECKING:
    from .protocol import Protocol

_LOGGER = logging.getLogger(__name__)


class Account:
    """Account class for HekrAPI

    Raises:
        ValueError: Account constructor is not provided possible ways to authenticate
        AccountUnauthenticatedException: Account did not authenticate prior to calling method

    Attributes:
        _username (str): Account username
        _password (str, optional): Account password (not required with token)
        _access_token (str, optional): Authentication 'Bearer' token (not required with password)
        _refresh_token (str, optional): Refresh token (not required with password)
        application_id (str): Application ID (has default value)
    """

    BASE_USER_URL = 'https://user-openapi.hekreu.me'
    BASE_AUTH_URL = 'https://uaa-openapi.hekr.me'

    ACCESS_TOKEN_EXPIRES_AFTER = timedelta(hours=24)
    REFRESH_TOKEN_EXPIRES_AFTER = timedelta(days=30)

    def __init__(self, username: Optional[str] = None,
                 password: Optional[str] = None,
                 access_token: Optional[str] = None,
                 refresh_token: Optional[str] = None,
                 reauthenticate_on_fail: bool = True,
                 default_timeout: int = DEFAULT_TIMEOUT,
                 application_id: str = DEFAULT_APPLICATION_ID,
                 application_name: str = DEFAULT_APPLICATION_NAME,
                 application_version: str = DEFAULT_APPLICATION_VERSION,
                 application_type: str = DEFAULT_APPLICATION_TYPE,
                 os_version: str = DEFAULT_OS_VERSION,
                 pid: str = '00000000000',
                 client_type: str = 'ANDROID'):

        if not access_token and not (username and password):
            raise ValueError("at least one authentication method (access token, username/password) must be set up")

        if not (username and password):
            if username:
                raise ValueError("password not provided or empty")
            elif password:
                raise ValueError("username not provided or empty")
            elif not access_token:
                raise ValueError("neither authentication methods provided (username/password, access token)")
            self._username = None
            self._password = None
        else:
            self._username = username
            self._password = password

        if access_token:
            self._access_token = access_token
        else:
            self._access_token = None

        self.application_id = application_id
        self.application_name = application_name
        self.application_version = application_version
        self.application_type = application_type
        self.os_version = os_version
        self.default_timeout = default_timeout

        self._refresh_token = refresh_token
        self._refresh_token_expires_at = datetime.utcnow()
        self._access_token_expires_at = datetime.utcnow()
        self._user_id = None
        self._pid = pid
        self._client_type = client_type

        self.reauthenticate_on_fail = reauthenticate_on_fail

        self._connectors: Dict[Tuple[str, int], CloudConnector] = {}

    def __str__(self):
        return 'Account("{}", {})'.format(
            self._username,
            self._user_id,
        )

    def __repr__(self):
        return '<Hekr:Account[username={}, user_id={}, access_token_expired={}, refresh_token_expired={}]>'.format(
            self._username,
            self._user_id,
            self.access_token_expired,
            self.refresh_token_expired
        )

    def get_device_control_connector(self, host: str, port: int = 186):
        """
        Get connector for account to device control API.
        :param host: WebSocket host
        :param port: WebSocket port (default: 186)
        :return:
        """
        if not self._access_token:
            raise AccountNotAuthenticatedException(self)

        key = (host, port)
        if key not in self._connectors:
            connector = CloudConnector(
                access_token=self._access_token,
                websocket_host=host,
                websocket_port=port,
                application_id=self.application_id
            )
            self._connectors[key] = connector
            return connector
        return self._connectors[key]

    @property
    def access_token_expired(self) -> bool:
        """
        Check whether access token is expired.
        Access token not being set at all yields a positive result.
        Access tokens are valid for 24 hours since last refresh.
        """
        if self._access_token is None:
            return True
        return (self._access_token_expires_at - datetime.utcnow()) >= self.ACCESS_TOKEN_EXPIRES_AFTER

    @property
    def refresh_token_expired(self) -> bool:
        """
        Check whether refresh token is expired.
        Refresh token not being set at all yields a positive result.
        Refresh tokens are valid for 30 days since last refresh.
        """
        if self._refresh_token is None:
            return True
        return (self._refresh_token_expires_at - datetime.utcnow()) >= self.REFRESH_TOKEN_EXPIRES_AFTER

    @property
    def connectors(self) -> Dict[Tuple[str, int], CloudConnector]:
        """
        Connectors accessor.
        :return: (Host, Port) -> Cloud connector
        """
        return self._connectors

    @property
    def devices(self) -> Dict[DeviceID, 'Device']:
        """
        Devices accessor.
        :return: Device ID -> Device object
        """
        attached_devices = dict()
        for connector in self._connectors.values():
            attached_devices.update(connector.devices)
        return attached_devices

    def _generate_auth_header(self):
        """
        Generate authentication header for HTTP requests.
        :raises AccountUnauthenticatedException: When access token is not set
        :raises AccessTokenExpiredException: When access token is considered expired
        :return:
        """

    async def _do_request(self,
                          url: str,
                          method: str = 'GET',
                          headers: Optional[Dict[str, str]] = None,
                          use_session: Optional[ClientSession] = None,
                          authenticated: bool = True,
                          **request_args) -> str:
        """
        Perform request to HTTP API.
        :param url: URL to request
        :param headers: Headers to pass (will be merged with auth headers if an account is provided)
        :param account: Account to use for authentication
        :param request_args: Additional arguments to pass to requester
        :return:
        """
        if authenticated:
            if self._access_token is None:
                raise AccessTokenMissingException(self)
            elif self.access_token_expired:
                raise AccessTokenExpiredException(self)

            request_headers = {'Authorization': 'Bearer ' + self._access_token}
            if headers is not None:
                request_headers.update(headers)
        else:
            request_headers = headers

        async def post_request(request_session: ClientSession):
            _LOGGER.debug('Making %s request to %s (headers: %s, args: %s)' % (method, url, headers, request_args))
            async with request_session.request(method, url, headers=request_headers, **request_args) as response:
                _LOGGER.debug('Full request URL: %s' % response.url)
                _LOGGER.debug('Full request headers: %s' % dict(response.headers))
                return response.status, await response.text()

        if use_session:
            status, content = await post_request(use_session)
        else:
            async with ClientSession() as session:
                status, content = await post_request(session)

        _LOGGER.debug('Received response (%d): %s' % (status, content))

        if status in (401, 403):
            raise AccountCredentialsException(self)
        elif status in range(400, 600):
            raise AccountErrorResponseException(self, status, content)
        elif status != 200:
            raise AccountUnknownResponseException(self, status)

        return content

    async def _do_json_request(self,
                               url: str,
                               method: Optional[str] = None,
                               headers: Optional[Dict[str, Any]] = None,
                               json: Optional[Dict[str, Any]] = None,
                               **request_args) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        if method is None:
            method = 'GET' if json is None else 'POST'
        elif method.lower() == 'get' and json is not None:
            raise ValueError('GET requests are incompatible with json')

        error_status = None
        request_headers = {'Accept': 'application/json'}
        if headers is not None:
            request_headers.update(headers)

        try:
            content = await self._do_request(
                url=url,
                method=method,
                headers=request_headers,
                json=json,
                **request_args
            )
        except AccountErrorResponseException as e:
            error_status = e.args[1]
            content = e.args[2]

        try:
            decoded = loads(content)
            if error_status is not None:
                raise AccountErrorResponseException(
                    self,
                    decoded.get('code', error_status),
                    decoded.get('desc', content)
                )
            return decoded
        except JSONDecodeError as e:
            raise AccountJSONInvalidException(self, e) from None

    # authentication handling
    def _process_auth_response(self, response: Dict[str, Any]) -> NoReturn:
        if not response:
            raise ValueError('response dictionary cannot be empty')

        if self._refresh_token != response['refresh_token']:
            self._refresh_token_expires_at = datetime.utcnow() + timedelta(days=30)

        _LOGGER.info('Successful authentication for account %s' % self)

        self._refresh_token = response['refresh_token']
        self._access_token = response['access_token']
        self._user_id = response['user']
        self._access_token_expires_at = datetime.utcnow() + timedelta(seconds=response['expires_in'])

    async def authenticate(self, attempt_refresh: bool = True, expires_in: int = 86400) -> NoReturn:
        """Authenticate account with Hekr"""
        if attempt_refresh and self._refresh_token:
            if not self.refresh_token_expired:
                payload = {
                    'refresh_token': self._refresh_token,
                    'expires_in': expires_in,
                }
                try:
                    response = await self._do_json_request(
                        url=self.BASE_AUTH_URL + '/token/refresh',
                        authenticated=False,
                        json=payload
                    )
                    self._process_auth_response(response)
                    return
                except (AccountCredentialsException, AccountUnknownResponseException) as e:
                    _LOGGER.debug('Refreshing token failed: %s; attempting regular authentication' % e)

        payload = {
            'username': self._username,
            'password': self._password,
            'pid': self._pid,
            'clientType': self._client_type,
            'appLoginInfo': {
                "id": self.application_id,
                "os": self.os_version,
                "type": self.application_type,
                "appVersion": self.application_version,
                "name": self.application_name,
            }
        }

        response = await self._do_json_request(
            url=self.BASE_AUTH_URL + '/login',
            authenticated=False,
            json=payload
        )
        self._process_auth_response(response)

    # Device info getters
    async def get_devices_info(self,
                               update_existing_devices: bool = True,
                               device_type: Optional['DeviceType'] = None,
                               by_control_key: Optional[Union[str, Tuple[str]]] = None,
                               from_folder: Optional[Union[str, Sequence[str]]] = None,
                               from_group: Optional[Union[str, Sequence[str]]] = None,
                               devices_per_request: int = 20) -> List[DeviceInfo]:
        if devices_per_request < 1:
            raise ValueError('devices per request cannot be less than 1')
        elif devices_per_request > 20:
            raise ValueError('devices per request cannot be greater than 20')

        base_params = dict()
        from_url = self.BASE_USER_URL + '/device'
        for key, value in [('folderId', from_folder), ('groupId', from_group), ('ctrlKey', by_control_key)]:
            if value is not None:
                base_params[key] = value if isinstance(value, str) else ','.join(value)

        if device_type is not None:
            base_params['type'] = device_type.name

        current_page = 0

        devices_info = list()
        async with ClientSession() as session:
            more_devices = True
            while more_devices:
                base_params.update({
                    'page': current_page,
                    'size': devices_per_request,
                })

                print(base_params)

                response_devices_info = await self._do_json_request(
                    url=from_url,
                    params=base_params,
                    use_session=session,
                )

                more_devices = (len(response_devices_info) >= devices_per_request)
                current_page += 1

                devices_info.extend([
                    DeviceInfo(device_info)
                    for device_info in response_devices_info
                ])

        if update_existing_devices:
            existing_devices = self.devices
            for device_info in devices_info:
                existing_device = existing_devices.get(device_info.device_id)
                if existing_device is not None:
                    existing_device.device_info = device_info

        return devices_info

    get_independent_devices_info = partialmethod(get_devices_info, device_type=DeviceType.INDEPENDENT)
    get_sub_devices_info = partialmethod(get_devices_info, device_type=DeviceType.SUB)
    get_gateway_devices_info = partialmethod(get_devices_info, device_type=DeviceType.GATEWAY)

    async def _update_connectors(self):
        for connector in self._connectors.values():
            connector.access_token = self._access_token

    def update_devices_from_info(self, devices_info: Union[DeviceInfo, Iterable[DeviceInfo]]) -> NoReturn:
        if isinstance(devices_info, DeviceInfo):
            devices_info = [devices_info]

        current_devices = self.devices
        for device_info in devices_info:
            device = current_devices.get(device_info.device_id)
            if device is not None:
                device.device_info = device_info

    def create_devices_from_info(self,
                                 devices_info: Union[DeviceInfo, Iterable[DeviceInfo]],
                                 protocols: Optional[Iterable['Protocol']] = None) -> List[Device]:
        """
        Create device objects attached to account based on provided info.
        :param devices_info: Information about devices (ex. via `get_devices`)
        :param protocols: Use specified protocols for detection
        :return: List of devices that got attached to account.
        """
        new_devices = []
        for device_info in ([DeviceInfo] if isinstance(devices_info, DeviceInfo) else devices_info):
            cloud_connector = self.get_device_control_connector(host=device_info.cloud_connect_host)
            new_devices.append(Device(device_info, protocol=protocols, cloud_connector=cloud_connector))

        return new_devices

    # various implemented requests
    async def get_captcha_image(self, file: Optional[BinaryIO] = None) -> Union[Tuple[str, str], str]:
        """
        Retrieve captcha image and solving ID.
        :param file: (optional) Provide output stream to put image into; this will cause this method
                     to only return the identifier for captcha solving
        :return: Tuple[Captcha solving identifier, base64-encoded captcha] / Captcha solving identifier
        """
        if not (file is None or file.writable()):
            raise ValueError('output stream does not appear to be writable')

        response = await self._do_json_request(
            url=self.BASE_AUTH_URL + '/api/v1/captcha',
            authenticated=False,
        )
        if file is None:
            return response['rid'], response['png']

        from base64 import b64decode
        file.write(b64decode(response['png']))
        return response['rid']

    async def check_captcha(self, captcha_identifier: str, solution: str):
        response = await self._do_json_request(
            url=self.BASE_AUTH_URL + '/images/checkCaptcha',
            params={'rid': captcha_identifier, 'code': solution}
        )
        print(response)

    async def get_bind_network_password(self, ssid: str) -> str:
        """Get network password for binding"""
        response = await self._do_json_request(
            url=self.BASE_USER_URL + '/getPINCode',
            method='GET',
            params={"ssid": ssid}
        )
        return response['PINCode']
