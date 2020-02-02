# -*- coding: utf-8 -*-
"""Account class module for HekrAPI"""
import logging
from json import JSONDecodeError, loads
from typing import Dict, Optional, Tuple

from aiohttp import ClientSession

from .const import DEFAULT_APPLICATION_ID
from .device import Device, CloudConnector
from .exceptions import AccountUnauthenticatedException, AccountDevicesUpdateFailedException, HekrAPIException

_LOGGER = logging.getLogger(__name__)


class Account:
    """Account class for HekrAPI

    Raises:
        ValueError: Account constructor is not provided possible ways to authenticate
        AccountUnauthenticatedException: Account did not authenticate prior to calling method

    Attributes:
        __username (str): Account username
        __password (str, optional): Account password (not required with token)
        __token (str, optional): Authentication 'Bearer' token (not required with password)
        __devices (dict): Dictionary with 'Device' objects belonging to account
        application_id (str): Application ID (has default value)
    """

    BASE_URL = 'https://user-openapi.hekreu.me'

    def __init__(self, username: Optional[str] = None, password: Optional[str] = None,
                 token: Optional[str] = None,
                 application_id: str = DEFAULT_APPLICATION_ID):
        # @TODO: refactor after enabling authentication support
        if not token and not (username and password):
            raise HekrAPIException("At least one authentication method (token, username/password) must be set up")

        self.application_id = application_id

        self.__username = username
        self.__password = password
        self.__token = token

        self.__connectors = {}

        self.__devices: Dict[str, Device] = {}

    def get_connector(self, connect_host: str, connect_port: int = 186):
        if not self.__token:
            raise AccountUnauthenticatedException(account=self)

        key = (connect_host, connect_port)
        if key not in self.__connectors:
            connector = CloudConnector(
                token=self.__token,
                connect_host=connect_host,
                connect_port=connect_port,
                application_id=self.application_id
            )
            self.__connectors[key] = connector
            return connector
        return self.__connectors[key]

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
        if not self.__token:
            raise AccountUnauthenticatedException(account=self)
        return {'Authorization': 'Bearer ' + self.__token}

    def authenticate(self):
        """Authenticate account with Hekr"""

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
                    try:
                        response_list = loads(content)
                    except JSONDecodeError:
                        raise AccountDevicesUpdateFailedException(account=self,
                                                                  response=response,
                                                                  reason='Received non-JSON response')

                    if response.status != 200:
                        await session.close()
                        reason = 'Account credentials incorrect' if response.status in (401, 403) \
                            else 'Unknown HTTP error'
                        raise AccountDevicesUpdateFailedException(account=self, response=response, reason=reason)

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
