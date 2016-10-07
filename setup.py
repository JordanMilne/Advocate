import re
import sys
from codecs import open

import setuptools
from setuptools.command.test import test as TestCommand


requires = [
    'requests <3.0, >=2.4',
    'six',
    "pyasn1",
    "pyopenssl",
    "ndg-httpsclient",
    'netifaces>=0.10.5',
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


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


setuptools.setup(
    name='advocate',
    version=version,
    packages=packages,
    install_requires=requires,
    tests_require=[
        "httpbin==0.4.0",
        "mock",
        "pytest==2.8.7",
        "pytest-cov==2.1.0",
        "pytest-httpbin==0.0.7",
        "requests-futures",
        "requests-mock",
    ],
    cmdclass={'test': PyTest},
    setup_requires=[
        'pytest-runner',
    ],
    url='https://github.com/JordanMilne/Advocate',
    license='Apache 2',
    author='Jordan Milne',
    author_email='advocate@saynotolinux.com',
    test_suite='test_advocate',
    keywords="http requests security ssrf proxy rebinding advocate",
    description=('A wrapper around the requests library for safely '
                 'making HTTP requests on behalf of a third party'),
    long_description=readme,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP',
    ],
)
