#!/usr/bin/env python

import os
from os import path
from setuptools import setup, find_packages

here = path.abspath(path.dirname(__file__))

datadir = os.path.join('.','misc')
datafiles = [(d, [os.path.join(d,f) for f in files])
            for d, folders, files in os.walk(datadir)]
setup(
    name='apt2',
    version='1.0.0',
    description='APT2 - An Automated Penetration Testing Toolkit',
    long_description='This tool will perform an NMap scan or import the results of a scan from an external scanning'
                     'tool. The processesd results will be used to launch exploit and enumeration modules according to '
                     'the configurable Safe Level and enumerated service information.',
    url='https://github.com/MooseDojo/apt2',
    author='Adam Compton & Austin Lane',
    author_email='adam.compton@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Hacker',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='apt2 pentesting automation',
    packages=find_packages(),
    data_files = datafiles,
    install_requires=[
        'python-nmap',
        'pysmb',
        'yattag',
        'scapy',
        'ftputil',
        'msgpack-python',
        'click', # fix issue with shodan installation
        'shodan',
        'ipwhois',
    ],
    entry_points={
        'console_scripts': [
            'apt2=apt2:main',
        ],
    },
    include_package_data=True,
)
