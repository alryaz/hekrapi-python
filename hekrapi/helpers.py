""" Helpers for Hekr API """
import re
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    pass

SENSITIVE_INFO_MATCH = re.compile(r'(["\'](ctrlKey|token)"\s*:\s*")[^"]+(["\'])')


def sensitive_info_filter(content: Union[str, bytes]) -> str:
    """
    Filters sensitive information from string for logs.

    :param content: Content to filter.
    :type content: str
    :return: Filtered content.
    :rtype: str
    """
    return SENSITIVE_INFO_MATCH.sub(r'\1<redacted>\3', str(content))


def device_id_from_mac_address(mac_address: Union[str, bytearray]) -> str:
    """
    Convert device's physical address to a device ID
    :param mac_address: MAC-address in dash/colon/spaced/concatenated format
    :type mac_address: str, bytes, bytearray
    :return: Device ID
    :rtype: str
    """
    if isinstance(mac_address, (bytes, bytearray)):
        mac_address = mac_address.hex()

    for delimiter in [':', '-', ' ']:
        mac_address = mac_address.replace(delimiter, '')

    mac_address = mac_address.upper()
    return 'ESP_2M_' + mac_address
