""" Helpers for Hekr API """
__all__ = [
    'sensitive_info_filter',
    'device_id_from_mac_address',
    'create_callback_task'
]
from asyncio import iscoroutinefunction, get_running_loop, create_task
import re
from typing import TYPE_CHECKING, Union, Callable, Any, Optional

if TYPE_CHECKING:
    from logging import Logger
    try:
        from asyncio import Task
    except ImportError:
        Task = Any

SENSITIVE_INFO_MATCH = re.compile(r'(["\'](ctrlKey|token)"\s*:\s*")[^"]+(["\'])', re.IGNORECASE | re.MULTILINE)


def sensitive_info_filter(content: Union[str, bytes]) -> str:
    """
    Filters sensitive information from string for logs.

    :param content: Content to filter.
    :type content: str
    :return: Filtered content.
    :rtype: str
    """
    return str(content)
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


def create_callback_task(callback: Callable, *args, executor: Any = None, logger: Optional['Logger'] = None,
                         suppress_exceptions: bool = True) -> 'Task':
    """
    Create callback task helper.
    :param callback: Callback function (async supported)
    :param args: Arguments to pass to the callback
    :param executor: Callback executor (for sync functions)
    :param logger: (optional) Logger to append exception to (defaults to current logger)
    :param suppress_exceptions: Do not raise callback exceptions (only print them in logger) (default: true)
    :return: Callback task
    """
    if logger is None:
        from logging import getLogger
        logger = getLogger(__name__)

    loop = get_running_loop()

    async def callback_task() -> Any:
        # noinspection PyBroadException
        try:
            if iscoroutinefunction(callback):
                await callback(*args)
            else:
                await loop.run_in_executor(executor, callback, *args)

        except BaseException:
            if suppress_exceptions:
                logger.exception('Encountered exception while running callback %s' % callback)
                return False
            raise

    return create_task(callback_task())
