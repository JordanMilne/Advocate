.. role:: python(code)
   :language: python

Advocate
========

.. image:: https://travis-ci.org/JordanMilne/Advocate.svg?branch=master
    :target: https://travis-ci.org/JordanMilne/Advocate/
.. image:: https://codecov.io/github/JordanMilne/Advocate/coverage.svg?branch=master
    :target: https://codecov.io/github/JordanMilne/Advocate

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



Examples
========


Advocate is more-or-less a drop-in replacement for requests. In most cases you can just replace requests with
advocate where necessary and be good to go:

.. code-block:: python

    import advocate
    print advocate.get("http://google.com/")

Advocate also provides a subclassed :python:`requests.Session` with sane defaults for 
blacklisting already set up:

.. code-block:: python

    import advocate
    sess = advocate.Session()
    print sess.get("http://google.com/")

If you have more nuanced rules but still want a drop-in replacement for
requests, there's :python:`RequestsAPIWrapper` :

.. code-block:: python

    from advocate import Blacklist, RequestsAPIWrapper
    from advocate.packages import ipaddress
    
    dougs_advocate = RequestsAPIWrapper(Blacklist(ip_blacklist={
        # Contains data incomprehensible to mere mortals
        ipaddress.ip_network("42.42.42.42/32")
    }))
    print dougs_advocate.get("http://42.42.42.42/")
    # ^ blocked!


TODO
====

Proper IPv6 Support?
--------------------

Advocate's IPv6 support is still a work-in-progress, since I'm not
that familiar with the spec, and there are so many ways to tunnel IPv4 over IPv6,
as well as other things we'd rather avoid. IPv6 records are ignored by default
for now, but you can enable them with :python:`allow_ipv6=True`.

It should mostly work as expected, but Advocate's approach might not even make sense with
most IPv6 deployments, see `Issue #3 <https://github.com/JordanMilne/Advocate/issues/3>`_ for
more info.

If you can think of any improvements to the IPv6 handling, please submit an issue or PR!


Caveats
=======

* This is beta-quality software, the API might change without warning!
* :python:`mount()` ing other adapters is disallowed to prevent Advocate's blacklisting adapters from being clobbered.
* Advocate does not (yet) support the use of HTTP proxies.
* Proper IPv6 support is still a WIP as noted above.

Acknowledgements
================

* https://github.com/fin1te/safecurl for inspiration
* https://github.com/kennethreitz/requests for the lovely requests module
* https://bitbucket.org/kwi/py2-ipaddress for the backport of ipaddress
