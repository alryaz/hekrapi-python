#!/usr/bin/env python3
from distutils.core import setup

version = 'v0.1.1'
setup(
    name='hekrapi',
    packages=['hekrapi', 'hekrapi.protocols'],
    version=version[1:],
    license='MIT',
    description='Python Hekr IoT API bindings',
    author='Alexander Ryazanov',
    author_email='alryaz@xavux.com',
    url='https://github.com/alryaz/hekrapi-python',
    download_url='https://github.com/alryaz/hekrapi-python/archive/' + version + '.tar.gz',
    keywords=['Hekr', 'API', 'Wisen', 'Smart Devices', 'IoT'],
    install_requires=[
        'aiohttp',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
)
