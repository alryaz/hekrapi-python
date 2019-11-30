from distutils.core import setup
setup(
  name = 'hekrapi',         # How you named your package folder (MyLib)
  packages = ['hekrapi', 'hekrapi.protocols'],   # Chose the same as "name"
  version = '0.0.3',      # Start with a small number and increase it with every change you make
  license='MIT',        # Chose a license from here: https://help.github.com/articles/licensing-a-repository
  description = 'Python Hekr IoT API bindings',
  author = 'Alexander Ryazanov',
  author_email = 'alryaz@xavux.com',
  url = 'https://github.com/alryaz/hekrapi-python',
  download_url = 'https://github.com/alryaz/hekrapi-python/archive/0.0.1.tar.gz',
  keywords = ['Hekr', 'API', 'Wisen', 'Smart Devices', 'IoT'],   # Keywords that define your package best
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
