__version__ = "0.6.2"

from requests import utils
from requests.models import Request, Response, PreparedRequest
from requests.status_codes import codes
from requests.exceptions import (
    RequestException, Timeout, URLRequired,
    TooManyRedirects, HTTPError, ConnectionError
)

from .adapters import ValidatingHTTPAdapter
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
from .addrvalidator import AddrValidator
from .exceptions import UnacceptableAddressException
