__version__ = "0.3.2"

from requests import utils
from requests.models import Request, Response, PreparedRequest
from requests.status_codes import codes
from requests.exceptions import (
    RequestException, Timeout, URLRequired,
    TooManyRedirects, HTTPError, ConnectionError
)

from .adapters import BlacklistingHTTPAdapter
from .api import (
    request,
    get,
    post,
    head,
    options,
    put,
    patch,
    delete,
    RequestsAPIWrapper,
    Session,
)
from .blacklist import Blacklist
from .exceptions import UnacceptableAddressException
