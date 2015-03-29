from setuptools import setup

import re

requires = [
    'requests<3.0',
    'six',
]

version = ''
with open('advocate/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

setup(
    name='advocate',
    version=version,
    packages=['advocate'],
    install_requires=requires,
    url='https://github.com/JordanMilne/Advocate',
    license='Apache 2',
    author='Jordan Milne',
    author_email='advocate@saynotolinux.com',
    keywords="http requests security",
    description=('Set of tools based around the requests library for safely '
                 'making HTTP requests on behalf of a third party'),
)
