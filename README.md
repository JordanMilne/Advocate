# Advocate

Advocate is a set of tools based around the [requests library](https://github.com/kennethreitz/requests) for safely making
HTTP requests on behalf of a third party. Specifically, it aims to prevent 
common techniques that enable [SSRF attacks](https://cwe.mitre.org/data/definitions/918.html). 

Advocate was inspired by the [fin1te's SafeCurl project](https://github.com/fin1te/safecurl).

## This seems like it's been done before

There've been a few similar projects, but in my opinion Advocate's approach is the best because:

### It sees URLs the same as the underlying HTTP library

Parsing URLs is hard, and no two URL parsers seem to behave exactly the same. The tiniest
differences in parsing between your validator and the underlying HTTP library can lead
to vulnerabilities. For example, differences between PHP's `parse_url` and cURL's
URL parser [allowed a blacklist bypass in SafeCurl](https://github.com/fin1te/safecurl/issues/5).

Advocate doesn't do URL parsing at all, and lets `requests` handle it. Advocate only looks at the
address `requests` actually tries to open a socket to.

### It deals with DNS rebinding

Two consecutive calls to `socket.getaddrinfo` aren't guaranteed to return the same
info, depending on the system configuration. If the "safe" looking record TTLs between
the verification lookup and the lookup for actually opening the socket, we may end
up connecting to a very different server than the one we OK'd!

Advocate gets around this by only using one `getaddrinfo` call for both verification
and connecting the socket. In pseudocode:

```python
def connect_socket(host, port):
    for res in socket.getaddrinfo(host, port):
        # where `res` will be a tuple containing the IP for the host
        if not is_blacklisted(res):
            # ... connect the socket using `res`
```

See Wikipedia's article on [DNS rebinding attacks](https://en.wikipedia.org/wiki/DNS_rebinding) for more info.

### It handles redirects

Most of the other SSRF-prevention libs cover this, but I've seen a lot
of sample code online that doesn't. Advocate will catch it since it inspects
*every* connection attempt the underlying HTTP lib makes. 

### It understands IPv6

Admittedly, Advocates IPv6 support is still a work-in-progress, since I'm not
that familiar with the spec, and there are so many ways to tunnel IPv4 over IPv6,
as well as other things we'd rather avoid. IPv6 records are ignored by default
for now, but you can enable them with `allow_ipv6=True`.

If you can think of any improvements to the IPv6 handling, please submit an issue or PR!

## Examples

Advocate is a drop-in replacement for `requests`, just replace `requests` with
`advocate` where necessary and you should be good to go:

```python
import advocate
print advocate.get("http://google.com/")
```

Advocate also provides a subclassed `requests.Session` with sane defaults for 
blacklisting already set up:

```python
import advocate
sess = advocate.Session()
print sess.get("http://google.com/")
```

**TODO**: Examples for custom blacklist rules

## Caveats

* `mount()`ing other adapters is disallowed to prevent Advocate's blacklisting adapters
from being clobbered.

* Advocate hasn't been tested with HTTP proxies, it's the proxy's job to do the 
blacklisting for any requests that go through it. Any requests that bypass the
proxy should properly handle blacklisting.

* Proper IPv6 support is still a WIP as noted above

## Acknowledgements

* https://github.com/fin1te/safecurl for inspiration
* https://github.com/kennethreitz/requests for the lovely `requests` module
* https://bitbucket.org/kwi/py2-ipaddress for the backport of `ipaddress`
