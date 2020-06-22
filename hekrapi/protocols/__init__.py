""" Protocols implemented in Python for Hekr API """
import pkgutil

__all__ = ['PROTOCOLS']

PROTOCOLS = dict()
DESCRIPTIONS = dict()

# borrowed from https://stackoverflow.com/a/3365846
for loader, module_name, is_pkg in pkgutil.walk_packages(__path__):
    __all__.append(module_name)
    _module = loader.find_module(module_name).load_module(module_name)

    if hasattr(_module, 'PROTOCOL'):
        globals()[module_name] = _module
        PROTOCOLS[module_name] = _module.PROTOCOL
        DESCRIPTIONS[module_name] = getattr(_module, '__doc__', None)
