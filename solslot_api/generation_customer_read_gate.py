"""One versioned read contract shared by current API and deployed web gate.

No POST, owner authorization, signing or funding permission is granted here.
Routes still enforce their native owner and generation checks after admission.
"""
import re

H = r'0x[0-9a-f]{64}'
READS = re.compile(r'(?:/customer/registration/(?:profile|lookup|reviews/'+H+r')'
    r'|/customer/session/'+H+r'|/customer/vaults/'+H+r'/journey|/customer/identity/profile'
    r'|/customer/identity/enrollments/'+H+r'(?:/session|/relay/recovery)?)\Z')


def current_read_allowed(method, path):
    if (not isinstance(path, str) or '\\' in path or '%' in path or '//' in path
            or any(value in ('.', '..') for value in path.split('/'))):
        return False
    return method in ('GET', 'HEAD') and READS.fullmatch(path) is not None


class CurrentCustomerReadGate:
    def __init__(self, app, *, retained):
        self.app, self.retained = app, retained

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http' and current_read_allowed(scope['method'], scope.get('path', '')):
            return await self.app(scope, receive, send)
        return await self.retained(scope, receive, send)
