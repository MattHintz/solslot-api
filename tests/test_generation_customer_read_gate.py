"""A registered current status route must also exist in the deployed read gate."""
import re
import pytest
from solslot_api.generation_customer_read_gate import current_read_allowed
from solslot_api.generation_customer_routes import router, session_router
from solslot_api.generation_customer_identity_routes import router as identity_router
from solslot_api.generation_customer_portfolio_routes import router as portfolio_router


def test_every_current_owner_status_get_has_web_gate_parity():
    checked = []
    for surface in (router, session_router, identity_router, portfolio_router):
        for route in surface.routes:
            if 'GET' not in route.methods:
                continue
            path = re.sub(r'\{[^}]+\}', '0x'+'a1'*32, route.path)
            assert current_read_allowed('GET', path), route.path
            assert current_read_allowed('HEAD', path), route.path
            assert not current_read_allowed('POST', path), route.path
            checked.append(route.path)
    assert '/customer/vaults/{launcher}/journey' in checked
    assert len(checked) >= 8


@pytest.mark.parametrize('method,path', [
    ('GET','/sols/vaults/0x'+'a1'*32+'/journey'),
    ('POST','/customer/vaults/0x'+'a1'*32+'/journey'),
    ('POST','/customer/purchases'), ('GET','/customer/vaults/../journey'),
    ('GET','/customer/vaults/%2e%2e/journey'), ('GET','//customer/identity/profile'),
    ('GET','/customer/identity/profile/'), ('DELETE','/customer/session/0x'+'a1'*32),
])
def test_no_retired_path_alias_or_financial_permission(method, path):
    assert not current_read_allowed(method, path)
