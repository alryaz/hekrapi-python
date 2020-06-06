hekrapi-python
======================
> Hekr API library written in Python
>
>[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
>[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/alryaz/hass-hekr-component/graphs/commit-activity)
>[![Donate Yandex](https://img.shields.io/badge/donate-Yandex-red.svg)](https://money.yandex.ru/to/410012369233217)
>[![Donate PayPal](https://img.shields.io/badge/donate-Paypal-blueviolet.svg)](https://www.paypal.me/alryaz)

The module provides interfacing with Hekr-enabled devices and accounts, exposing them as interactable objects.

Documentation is available within code (will be generated into devdocs with more comments in the future),
and a reference implementation (integration for _HomeAssistant_ automation system) is available
on GitHub: [alryaz/hass-hekr-component](https://github.com/alryaz/hass-hekr-component)

In its current state, the module supports:
- Local device communication (tested with a single device type only)
- Cloud device communication with account login (tested with a single device type only)
- Protocol skeleton (example provided for a _Smart Power Meter_ in `hekrapi/protocols/power_meter.py`)
- Command exchange (transparent JSON operation is supported)

Should you be willing to contribute to the project, create a forked version of it.  
More devices will be added upon discovery of such. Please, contact me on Telegram ([@alryaz](https://t.me/alryaz)) or
message me via E-mail ([alryaz@xavux.com](mailto:alryaz@xavux.com)) if you find one, so we can work out a possible
solution to add support for it. 
