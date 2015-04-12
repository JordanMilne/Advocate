import socket
from socket import timeout as SocketTimeout

from requests.packages.urllib3.connection import HTTPSConnection, HTTPConnection
from requests.packages.urllib3.exceptions import ConnectTimeoutError
from requests.packages.urllib3.util.connection import _set_socket_options

from .exceptions import UnacceptableAddressException


def advocate_getaddrinfo(host, port):
    addrinfo = socket.getaddrinfo(
        host,
        port,
        0,
        socket.SOCK_STREAM,
        0,
        # We need what the DNS client sees the hostname as, correctly handles
        # IDNs and tricky things like `private.foocorp.org\x00.google.com`.
        # All IDNs will be converted to punycode.
        socket.AI_CANONNAME,
    )
    if addrinfo:
        # Apparently the canonical name is only included in the first record?
        # Add it to all of them.
        assert(len(addrinfo[0]) == 5)
        canonname = addrinfo[0][3]
        addrinfo = map(lambda x: (x[0], x[1], x[2], canonname, x[4]), addrinfo)
    return tuple(addrinfo)


# Lifted from requests' urllib3, which in turn lifted it from `socket.py`. Oy!
def _create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                       source_address=None, socket_options=None,
                       blacklist=None):
    """Connect to *address* and return the socket object.

    Convenience function.  Connect to *address* (a 2-tuple ``(host,
    port)``) and return the socket object.  Passing the optional
    *timeout* parameter will set the timeout on the socket instance
    before attempting to connect.  If no *timeout* is supplied, the
    global default timeout setting returned by :func:`getdefaulttimeout`
    is used.  If *source_address* is set it must be a tuple of (host, port)
    for the socket to bind as a source address before making the connection.
    An host of '' or port 0 tells the OS to use the default.
    """

    host, port = address
    err = None
    addrinfo = advocate_getaddrinfo(host, port)
    if addrinfo:
        for res in addrinfo:
            # Are we allowed to connect with this result?
            if blacklist and not blacklist.is_addrinfo_allowed(res):
                continue
            af, socktype, proto, canonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)

                # If provided, set socket level options before connecting.
                # This is the only addition urllib3 makes to this function.
                _set_socket_options(sock, socket_options)

                if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(sa)
                return sock

            except socket.error as _:
                err = _
                if sock is not None:
                    sock.close()
                    sock = None

        # If we got here, none of the results were acceptable
        err = UnacceptableAddressException(address)
    if err is not None:
        raise err
    else:
        raise socket.error("getaddrinfo returns an empty list")


# TODO: Is there a better way to add this to multiple classes with different
# base classes? I tried a mixin, but it used the base method instead.
def _blacklisting_new_conn(self):
    """ Establish a socket connection and set nodelay settings on it.

    :return: New socket connection.
    """
    extra_kw = {"blacklist": self._blacklist}
    if self.source_address:
        extra_kw['source_address'] = self.source_address

    if self.socket_options:
        extra_kw['socket_options'] = self.socket_options

    try:
        conn = _create_connection(
            (self.host, self.port),
            self.timeout,
            **extra_kw
        )

    except SocketTimeout:
        raise ConnectTimeoutError(
            self, "Connection to %s timed out. (connect timeout=%s)" %
            (self.host, self.timeout))

    return conn


# Don't silently break if the private API changes across urllib3 versions
assert(hasattr(HTTPConnection, '_new_conn'))
assert(hasattr(HTTPSConnection, '_new_conn'))


class BlacklistingHTTPConnection(HTTPConnection):
    _new_conn = _blacklisting_new_conn

    def __init__(self, *args, **kwargs):
        self._blacklist = kwargs.pop("blacklist")
        HTTPConnection.__init__(self, *args, **kwargs)


class BlacklistingHTTPSConnection(HTTPSConnection):
    _new_conn = _blacklisting_new_conn

    def __init__(self, *args, **kwargs):
        self._blacklist = kwargs.pop("blacklist")
        HTTPSConnection.__init__(self, *args, **kwargs)
