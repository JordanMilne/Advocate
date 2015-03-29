from requests.packages.urllib3 import ProxyManager, PoolManager
from requests.packages.urllib3.poolmanager import SSL_KEYWORDS

from .connectionpool import (
    BlacklistingHTTPSConnectionPool,
    BlacklistingHTTPConnectionPool,
)


def _blacklisting_new_pool(self, scheme, host, port):
    """
    Create a new :class:`ConnectionPool` based on host, port and scheme.

    This method is used to actually create the connection pools handed out
    by :meth:`connection_from_url` and companion methods. It is intended
    to be overridden for customization.
    """
    pool_cls = self.POOL_CLASSES_BY_SCHEME[scheme]
    kwargs = self.connection_pool_kw
    if scheme == 'http':
        kwargs = self.connection_pool_kw.copy()
        for kw in SSL_KEYWORDS:
            kwargs.pop(kw, None)

    return pool_cls(host, port, **kwargs)


class BlacklistingPoolManager(PoolManager):
    POOL_CLASSES_BY_SCHEME = {
        "http": BlacklistingHTTPConnectionPool,
        "https": BlacklistingHTTPSConnectionPool,
    }
    _new_pool = _blacklisting_new_pool


class BlacklistingProxyPoolManager(ProxyManager):
    POOL_CLASSES_BY_SCHEME = {
        "http": BlacklistingHTTPConnectionPool,
        "https": BlacklistingHTTPSConnectionPool,
    }
    _new_pool = _blacklisting_new_pool


def proxy_from_url(url, **kw):
    return BlacklistingProxyPoolManager(proxy_url=url, **kw)
