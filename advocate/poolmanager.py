from requests.packages.urllib3 import ProxyManager, PoolManager
from requests.packages.urllib3.poolmanager import SSL_KEYWORDS

from .connectionpool import (
    ValidatingHTTPSConnectionPool,
    ValidatingHTTPConnectionPool,
)

POOL_CLASSES_BY_SCHEME = {
    "http": ValidatingHTTPConnectionPool,
    "https": ValidatingHTTPSConnectionPool,
}


def _validating_new_pool(self, scheme, host, port):
    """
    Create a new :class:`ConnectionPool` based on host, port and scheme.

    This method is used to actually create the connection pools handed out
    by :meth:`connection_from_url` and companion methods. It is intended
    to be overridden for customization.
    """
    # XXX: in urllib3 this uses the module-level `pool_classes_by_scheme` :(
    # maybe submit a patch upstream to use a class attr instead so we don't
    # have to dupe the whole method to use different connection pools?
    pool_cls = self.POOL_CLASSES_BY_SCHEME[scheme]
    kwargs = self.connection_pool_kw
    if scheme == 'http':
        kwargs = self.connection_pool_kw.copy()
        for kw in SSL_KEYWORDS:
            kwargs.pop(kw, None)

    return pool_cls(host, port, **kwargs)


# Don't silently break if the private API changes across urllib3 versions
assert(hasattr(PoolManager, '_new_pool'))


class ValidatingPoolManager(PoolManager):
    POOL_CLASSES_BY_SCHEME = POOL_CLASSES_BY_SCHEME.copy()
    _new_pool = _validating_new_pool
