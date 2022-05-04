#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from setuptools import setup, find_packages


def _read(filename):
    with open(filename) as f:
        return f.read()

# Load package version.
exec(_read('xojo_tools/_version.py'))

setup(
    name='xojo-tools',
    version=__version__,
    description='Xojo Tools',
    long_description=_read('README.md'),
    long_description_content_type='text/markdown',
    url='https://github.com/kmaehashi/xojo-tools',
    author='Kenichi Maehashi',
    author_email='webmaster@kenichimaehashi.com',
    license='MIT',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'xojo-agree-eula=xojo_tools.agree_eula:_main',
            'xojo-ide-communicator=xojo_tools.ide_communicator:_main',
            'xojo-quote=xojo_tools.quote:_main',
        ],
    },
    test_suite = 'tests',
)
