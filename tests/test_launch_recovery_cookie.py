"""Exercise browser cookie routing with real pre-genesis wallet authentication."""
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from solslot_api.admin_security import router as security_router
from solslot_api.config import Settings
from solslot_api.launch_control import LAUNCH_COOKIE_NAME
from tests.test_launch_control import _client, _claim_and_enroll_owner


def test_existing_launch_cookie_migrates_to_recovery_and_logout_clears_it(tmp_path):
    original, _, settings = _client(tmp_path)
    settings.launch_cookie_path = "/protocol-api/admin/launch"
    original.app.include_router(security_router)
    app = FastAPI()
    app.mount("/protocol-api", original.app)
    with TestClient(app, base_url="http://testserver/protocol-api") as client:
        _, ceremony_id = _claim_and_enroll_owner(client)
        old_token = client.cookies.get(LAUNCH_COOKIE_NAME)
        assert client.get("/admin/security/status").status_code != 200

        settings.launch_cookie_path = Settings(_env_file=None).launch_cookie_path
        assert settings.launch_cookie_path == "/protocol-api/admin"
        workspace = client.get("/admin/launch/workspace")
        assert workspace.status_code == 200, workspace.text
        cookies = [c for c in client.cookies.jar if c.name == LAUNCH_COOKIE_NAME]
        assert len(cookies) == 1
        assert cookies[0].path == "/protocol-api/admin"
        assert cookies[0].value == old_token  # no new authority or extended JWT expiry
        assert cookies[0].expires > time.time()

        security = client.get("/admin/security/status")
        assert security.status_code == 200, security.text
        assert security.json()["actor"]["ceremonyId"] == ceremony_id
        assert security.json()["myRecoveryKit"] is None

        # Simulate an old cookie still present in another browser at sign-out.
        client.cookies.set(LAUNCH_COOKIE_NAME, old_token,
                           domain="testserver.local", path="/protocol-api/admin/launch")
        assert client.post("/admin/launch/auth/logout").status_code == 200
        assert not [c for c in client.cookies.jar if c.name == LAUNCH_COOKIE_NAME]
        assert client.get("/admin/security/status").status_code != 200
