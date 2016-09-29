
from setuptools import setup, find_packages

version = '0.3.1'

setup(
    name="alerta-pushover",
    version=version,
    description='Alerta plugin for Pushover',
    url='https://github.com/alerta/alerta-contrib',
    license='Apache License 2.0',
    author='Nick Satterly',
    author_email='nick.satterly@theguardian.com',
    packages=find_packages(),
    py_modules=['alerta_pushover'],
    install_requires=[
        'requests'
    ],
    include_package_data=True,
    zip_safe=True,
    entry_points={
        'alerta.plugins': [
            'pushover = alerta_pushover:PushMessage'
        ]
    }
)