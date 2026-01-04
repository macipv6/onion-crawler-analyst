# -*- coding: utf-8 -*-
import ssl, socks, socket, hashlib
from urllib.parse import urlparse

def get_tls_sha256(url: str, socks_host="tor", socks_port=9050, timeout=20) -> str | None:
    u = urlparse(url)
    if u.scheme != "https" or not u.hostname:
        return None
    host, port = u.hostname, u.port or 443

    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, socks_host, socks_port, rdns=True)
    s.settimeout(timeout)
    s.connect((host, port))

    ctx = ssl.create_default_context()
    with ctx.wrap_socket(s, server_hostname=host) as ssock:
        der = ssock.getpeercert(binary_form=True)
    return hashlib.sha256(der).hexdigest().upper()
