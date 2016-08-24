.. role:: python(code)
   :language: python

Advocate
========

.. image:: https://travis-ci.org/JordanMilne/Advocate.svg?branch=master
    :target: https://travis-ci.org/JordanMilne/Advocate/
.. image:: https://codecov.io/github/JordanMilne/Advocate/coverage.svg?branch=master
    :target: https://codecov.io/github/JordanMilne/Advocate
.. image:: https://img.shields.io/pypi/pyversions/advocate.svg
.. image:: https://img.shields.io/pypi/v/advocate.svg
    :target: https://pypi.python.org/pypi/advocate


Advocate is a set of tools based around the `requests library <https://github.com/kennethreitz/requests>`_ for safely making
HTTP requests on behalf of a third party. Specifically, it aims to prevent 
common techniques that enable `SSRF attacks <https://cwe.mitre.org/data/definitions/918.html>`_. 

Advocate was inspired by `fin1te's SafeCurl project <https://github.com/fin1te/safecurl>`_.

Installation
============

.. code-block:: bash

    pip install advocate

Advocate is officially supported on CPython 2.7+, CPython 3.4+ and PyPy 2. PyPy 3 may work as well, but 
you'll need a copy of the ipaddress module from elsewhere.

See it in action
================

If you want to try out Advocate to see what kind of things it catches, there's a `test site up on advocate.saynotolinux.com <http://advocate.saynotolinux.com/>`_.

Examples
========

Advocate is more-or-less a drop-in replacement for requests. In most cases you can just replace "requests" with
"advocate" where necessary and be good to go:

.. code-block:: python

    >>> import advocate
    >>> print advocate.get("http://google.com/")
    <Response [200]>

Advocate also provides a subclassed :python:`requests.Session` with sane defaults for
validation already set up:

.. code-block:: python

    >>> import advocate
    >>> sess = advocate.Session()
    >>> print sess.get("http://google.com/")
    <Response [200]>
    >>> print sess.get("http://localhost/")
    advocate.exceptions.UnacceptableAddressException: ('localhost', 80)

All of the wrapped request functions accept a :python:`validator` kwarg where you
can set additional rules:

.. code-block:: python

    >>> import advocate
    >>> validator = advocate.AddrValidator(hostname_blacklist={"*.museum",})
    >>> print advocate.get("http://educational.MUSEUM/", validator=validator)
    advocate.exceptions.UnacceptableAddressException: educational.MUSEUM

If you require more advanced rules than the defaults, but don't want to have to pass
the validator kwarg everywhere, there's :python:`RequestsAPIWrapper` . You can
define a wrapper in a common file and import it instead of advocate:

.. code-block:: python

    >>> from advocate import AddrValidator, RequestsAPIWrapper
    >>> from advocate.packages import ipaddress
    >>> dougs_advocate = RequestsAPIWrapper(AddrValidator(ip_blacklist={
    ...     # Contains data incomprehensible to mere mortals
    ...     ipaddress.ip_network("42.42.42.42/32")
    ... }))
    >>> print dougs_advocate.get("http://42.42.42.42/")
    advocate.exceptions.UnacceptableAddressException: ('42.42.42.42', 80)


Other than that, you can do just about everything with Advocate that you can
with an unwrapped requests. Advocate passes requests' test suite with the
exception of tests that require :python:`Session.mount()`.

Conditionally bypassing protection
==================================

If you want to allow certain users to bypass Advocate's restrictions, just
use plain 'ol requests by doing something like:

.. code-block:: python

    if user == "mr_skeltal":
        requests_module = requests
    else:
        requests_module = advocate
    resp = requests_module.get("http://example.com/doot_doot")


requests-futures support
========================

A thin wrapper around `requests-futures <https://github.com/ross/requests-futures>`_ is provided to ease writing async-friendly code:

.. code-block:: python

    >>> from advocate.futures import FuturesSession
    >>> sess = FuturesSession()
    >>> fut = sess.get("http://example.com/")
    >>> fut
    <Future at 0x10c717f28 state=finished returned Response>
    >>> fut.result()
    <Response [200]>

You can do basically everything you can do with regular :python:`FuturesSession` s and :python:`advocate.Session` s:

.. code-block:: python

    >>> from advocate import AddrValidator
    >>> from advocate.futures import FuturesSession
    >>> sess = FuturesSession(max_workers=20, validator=AddrValidator(hostname_blacklist={"*.museum"}))
    >>> fut = sess.get("http://anice.museum/")
    >>> fut
    <Future at 0x10c696668 state=running>
    >>> fut.result()
    Traceback (most recent call last):
    # [...]
    advocate.exceptions.UnacceptableAddressException: anice.museum


When should I use Advocate?
===========================

Any time you're fetching resources over HTTP for / from someone you don't trust!

When should I not use Advocate?
===============================

That's a tough one. There are a few cases I can think of where I wouldn't:

* When good, safe support for IPv6 is important
* When internal hosts use globally routable addresses and you can't guess their prefix to blacklist it ahead of time
* You already have a good handle on network security within your network

Actually, if you're comfortable enough with Squid and network security, you should set up a secured Squid instance on a segregated subnet
and proxy through that instead. Advocate attempts to guess whether an address references an internal host
and block access, but it's definitely preferable to proxy through a host can't access anything internal in the first place!

Of course, if you're writing an app / library that's meant to be usable OOTB on other people's networks, Advocate + a user-configurable
blacklist is probably the safer bet.


This seems like it's been done before
=====================================

There've been a few similar projects, but in my opinion Advocate's approach is the best because:

It sees URLs the same as the underlying HTTP library
----------------------------------------------------

Parsing URLs is hard, and no two URL parsers seem to behave exactly the same. The tiniest
differences in parsing between your validator and the underlying HTTP library can lead
to vulnerabilities. For example, differences between PHP's :python:`parse_url` and cURL's
URL parser `allowed a blacklist bypass in SafeCurl <https://github.com/fin1te/safecurl/issues/5>`_.

Advocate doesn't do URL parsing at all, and lets requests handle it. Advocate only looks at the
address requests actually tries to open a socket to.

It deals with DNS rebinding
---------------------------

Two consecutive calls to :python:`socket.getaddrinfo` aren't guaranteed to return the same
info, depending on the system configuration. If the "safe" looking record TTLs between
the verification lookup and the lookup for actually opening the socket, we may end
up connecting to a very different server than the one we OK'd!

Advocate gets around this by only using one :python:`getaddrinfo` call for both verification
and connecting the socket. In pseudocode:

.. code-block:: python

    def connect_socket(host, port):
        for res in socket.getaddrinfo(host, port):
            # where `res` will be a tuple containing the IP for the host
            if not is_blacklisted(res):
                # ... connect the socket using `res`

See `Wikipedia's article on DNS rebinding attacks <https://en.wikipedia.org/wiki/DNS_rebinding>`_ for more info.

It handles redirects sanely
---------------------------

Most of the other SSRF-prevention libs cover this, but I've seen a lot
of sample code online that doesn't. Advocate will catch it since it inspects
*every* connection attempt the underlying HTTP lib makes. 


TODO
====

Proper IPv6 Support?
--------------------

Advocate's IPv6 support is still a work-in-progress, since I'm not
that familiar with the spec, and there are so many ways to tunnel IPv4 over IPv6,
as well as other non-obvious gotchas. IPv6 records are ignored by default
for now, but you can enable by using an :python:`AddrValidator` with :python:`allow_ipv6=True`.

It should mostly work as expected, but Advocate's approach might not even make sense with
most IPv6 deployments, see `Issue #3 <https://github.com/JordanMilne/Advocate/issues/3>`_ for
more info.

If you can think of any improvements to the IPv6 handling, please submit an issue or PR!


Caveats
=======

* This is beta-quality software, the API might change without warning!
* :python:`mount()` ing other adapters is disallowed to prevent Advocate's validating adapters from being clobbered.
* Advocate does not, and might never support the use of HTTP proxies.
* Proper IPv6 support is still a WIP as noted above.

Acknowledgements
================

* https://github.com/fin1te/safecurl for inspiration
* https://github.com/kennethreitz/requests for the lovely requests module
* https://bitbucket.org/kwi/py2-ipaddress for the backport of ipaddress
* https://github.com/hakobe/paranoidhttp a similar project targeting golang
* https://github.com/uber-common/paranoid-request a similar project targeting Node
* http://search.cpan.org/~tsibley/LWP-UserAgent-Paranoid/ a similar project targeting Perl 5
