# -*- coding: utf-8 -*-
"""Account class module for HekrAPI"""

from typing import Union
from aiohttp import ClientSession

from .device import Device
from .const import DEFAULT_APPLICATION_ID
from .exceptions import AccountUnauthenticatedException, AccountDevicesUpdateFailedException


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
        """Device dictionary accessor

        Returns:
            dict -- dictionary of devices (device_id => Device object)
        """
        return self.__devices

    def authenticate(self):
        """Authenticate account with Hekr"""

    async def update_devices(self):
        """Update devices for account

        Raises:
            AccountUnauthenticatedException: [description]

        Returns:
            int -- New devices found (that do not exist within the __devices attribute)
        """

        if not self.__token:
            raise AccountUnauthenticatedException()

        base_url_devices = self.BASE_URL + '/devices?size={}&page={}'

        request_devices = 20
        current_page = 0

        new_devices = {}

        async with ClientSession() as session:
            more_devices = True
            while more_devices:
                request_url = base_url_devices.format(
                    request_devices,
                    current_page
                )

                async with session.get(
                        request_url,
                        headers={'Authorization': 'Bearer ' + self.__token}
                ) as response:
                    response_json = await response.json()

                    if response.status != 200:
                        session.close()
                        raise AccountDevicesUpdateFailedException(self, response)

                    more_devices = (len(response_json) == request_devices)

                    for device_attributes in response_json:
                        device_id = device_attributes['devTid']

                        if device_id in self.__devices:
                            self.__devices[device_id].set_control_key(
                                device_attributes['ctrlKey'])
                        else:
                            new_devices[device_id] = Device(
                                device_id=device_id,
                                control_key=device_attributes['ctrlKey'],
                                host=device_attributes['lanIp'],
                                application_id=self.application_id
                            )

            if new_devices:
                self.__devices.update(new_devices)

        return len(new_devices)
