import re


from codecs import open
from setuptools import setup

requires = [
    'requests <3.0, >=2.4',
    'six',
]

packages = [
    "advocate",
    "advocate.packages",
    "advocate.packages.ipaddress"
]

version = ''
with open('advocate/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

with open('README.rst', 'r', 'utf-8') as f:
    readme = f.read()

setup(
    name='advocate',
    version=version,
    packages=packages,
    install_requires=requires,
    url='https://github.com/JordanMilne/Advocate',
    license='Apache 2',
    author='Jordan Milne',
    author_email='advocate@saynotolinux.com',
    test_suite='test_advocate',
    keywords="http requests security ssrf proxy rebinding",
    description=('A set of tools based around the requests library for safely '
                 'making HTTP requests on behalf of a third party'),
    long_description=readme,
    classifiers=(
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5'
    ),
)
