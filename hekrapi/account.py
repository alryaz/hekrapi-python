# -*- coding: utf-8 -*-
"""Account class module for HekrAPI"""

from typing import Union
from aiohttp import ClientSession

from .device import Device
from .const import DEFAULT_APPLICATION_ID
from .exceptions import AccountUnauthenticatedException


class Account:
    """Account class for HekrAPI

    Attributes:
        __username (str): Account username
        __password (str, optional): Account password (not required with token)
        __token (str, optional): Authentication 'Bearer' token (not required with password)
        __devices (dict): Dictionary with 'Device' objects belonging to account
        application_id (str): Application ID
    """

    BASE_URL = 'https://user-openapi.hekreu.me'

    def __init__(self, username: str, password: Union[str, type(None)]=None,
                 token: Union[str, type(None)]=None,
                 application_id: str = DEFAULT_APPLICATION_ID):
        # @TODO: refactor after enabling authentication support
        if not token:  # and not password:
            raise ValueError(
                "at least one of arguments (password, token) should be set")

        self.application_id = application_id

        self.__username = username
        self.__password = password
        self.__token = token

        self.__devices = {}

    @property
    def devices(self):
        """Devices array accessor"""
        return self.__devices

    def authenticate(self):
        """Authenticate account with Hekr"""

    async def update_devices(self):
        """Fetch devices from account"""
        if not self.__token:
            raise AccountUnauthenticatedException()

        base_url_devices = self.BASE_URL + '/devices?size={}&page={}'

        request_devices = 20
        current_page = 0

        async with ClientSession() as session:
            more_devices = True
            found_devices = {}
            while more_devices:
                request_url = base_url_devices.format(
                    request_devices,
                    current_page
                )

                async with session.get(
                        request_url,
                        headers={'Authorization': 'Bearer ' + self.__token}
                ) as response:
                    devices_list = await response.json()
                    more_devices = (len(devices_list) == request_devices)

                    for device_attributes in devices_list:
                        if device_attributes['devTid'] in self.__devices:
                            self.__devices[device_attributes['devTid']].set_control_key(
                                device_attributes['ctrlKey'])
                        else:
                            found_devices[device_attributes['devTid']] = Device(
                                device_id=device_attributes['devTid'],
                                control_key=device_attributes['ctrlKey'],
                                host=device_attributes['lanIp'],
                                application_id=self.application_id
                            )

            if found_devices:
                self.__devices.update(found_devices)
