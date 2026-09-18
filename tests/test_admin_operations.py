from __future__ import annotations

import time

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys import keys as eth_keys
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from chia_rs.sized_bytes import bytes32
from solslot_puzzles.admin_operation_v1 import AdminOperationCoreV1

from solslot_api.admin_auth import AdminClaims, require_admin_jwt
from solslot_api.admin_operations import (
    AdminRoster,
    OperationStore,
    _public_operation,
    canonical_request_binding,
    get_operation_store,
    request_binding_hash,
    require_admin_operation,
    resolve_admin_roster,
    router,
)
from solslot_api.config import Settings, get_settings


OWNER = "0x" + "11" * 20
COADMIN = "0x" + "22" * 20


def test_production_roster_uses_completed_signed_rotations(monkeypatch) -> None:
    replacements = [
        ("0x" + f"{index + 1:02x}" * 20, "0x02" + f"{index + 4:02x}" * 32)
        for index in range(3)
    ]
    monkeypatch.setattr(
        "solslot_api.admin_operations.load_signed_public_artifact",
        lambda _settings: {"launcherIds": {"adminAuthority": "0x" + "ab" * 32}},
    )
    monkeypatch.setattr(
        "solslot_api.admin_operations.current_signed_admins",
        lambda _settings: replacements,
    )

    roster = resolve_admin_roster(Settings(runtime_environment="production"))

    assert roster.launcher_id == bytes32(b"\xab" * 32)
    assert roster.compressed_pubkeys == tuple(
        bytes.fromhex(item[1][2:]) for item in replacements
    )


def claims(subject: str = OWNER) -> AdminClaims:
    return AdminClaims(sub=subject, auth_type="evm", iat=1, exp=2_000_000_000)


def create_operation(
    store: OperationStore,
    *,
    binding: dict,
    now: int,
) -> tuple[str, bytes32]:
    payload_hash = request_binding_hash(binding)
    core = AdminOperationCoreV1(
        authority_launcher_id=bytes32(b"\x11" * 32),
        network="testnet11",
        operation="mint.publish",
        payload_hash=payload_hash,
        revision=4,
        nonce=bytes32(b"\x33" * 32),
        expires_at=now + 600,
    )
    value = store.create(core=core, binding=binding, created_by=OWNER, now=now)
    return value["operation_id"], payload_hash


def add_signature(store: OperationStore, operation_id: str, index: int, address: str, now: int) -> None:
    store.add_signature(
        operation_id=operation_id,
        admin_index=index,
        signer_address=address,
        compressed_pubkey="0x02" + f"{index + 1:02x}" * 32,
        signature="0x" + f"{index + 1:02x}" * 65,
        now=now,
    )


def test_two_coadmins_never_approve_without_slot_zero(tmp_path) -> None:
    store = OperationStore(tmp_path / "admin.db")
    now = int(time.time())
    binding = canonical_request_binding(
        method="POST", path="/admin/example", query=[], body={"value": 7}, if_match=None
    )
    operation_id, _ = create_operation(store, binding=binding, now=now)
    add_signature(store, operation_id, 1, COADMIN, now)
    add_signature(store, operation_id, 2, "0x" + "33" * 20, now)

    assert store.get(operation_id)["status"] == "pending"
    with pytest.raises(ValueError, match="lacks slot 0"):
        store.consume(
            operation_id=operation_id,
            expected_operation="mint.publish",
            expected_payload_hash=request_binding_hash(binding),
            caller=COADMIN,
            now=now,
        )


def test_presale_mutation_paths_can_be_bound_without_widening_other_paths() -> None:
    binding = canonical_request_binding(
        method="POST",
        path="/presales/0xabc/launch",
        query=[],
        body={"mode": "owner_gated"},
        if_match=None,
    )
    assert binding["path"] == "/presales/0xabc/launch"
    with pytest.raises(ValueError, match="authoritative"):
        canonical_request_binding(
            method="POST",
            path="/public/collections/example",
            query=[],
            body={},
            if_match=None,
        )


def test_exact_request_binding_is_single_use_and_requires_a_signer_jwt(tmp_path) -> None:
    store = OperationStore(tmp_path / "admin.db")
    now = int(time.time())
    binding = canonical_request_binding(
        method="POST", path="/admin/example", query=[], body={"value": 7}, if_match=None
    )
    operation_id, payload_hash = create_operation(store, binding=binding, now=now)
    add_signature(store, operation_id, 0, OWNER, now)
    add_signature(store, operation_id, 1, COADMIN, now)
    assert store.get(operation_id)["status"] == "approved"

    with pytest.raises(ValueError, match="did not sign"):
        store.consume(
            operation_id=operation_id,
            expected_operation="mint.publish",
            expected_payload_hash=payload_hash,
            caller="0x" + "44" * 20,
            now=now,
        )
    with pytest.raises(ValueError, match="does not match"):
        store.consume(
            operation_id=operation_id,
            expected_operation="mint.publish",
            expected_payload_hash=bytes32(b"\x99" * 32),
            caller=OWNER,
            now=now,
        )
    store.consume(
        operation_id=operation_id,
        expected_operation="mint.publish",
        expected_payload_hash=payload_hash,
        caller=OWNER,
        now=now,
    )
    with pytest.raises(ValueError, match="already consumed"):
        store.consume(
            operation_id=operation_id,
            expected_operation="mint.publish",
            expected_payload_hash=payload_hash,
            caller=OWNER,
            now=now,
        )


def test_http_dependency_rejects_jwt_only_and_consumes_owner_approval(
    tmp_path, monkeypatch
) -> None:
    store = OperationStore(tmp_path / "admin.db")
    settings = Settings(
        runtime_environment="test",
        admin_operation_approvals_enabled=True,
        admin_db_path=str(tmp_path / "admin.db"),
    )
    now = int(time.time())
    binding = canonical_request_binding(
        method="POST", path="/admin/example", query=[], body={"value": 7}, if_match=None
    )
    operation_id, _ = create_operation(store, binding=binding, now=now)
    add_signature(store, operation_id, 0, OWNER, now)
    add_signature(store, operation_id, 1, COADMIN, now)
    roster = AdminRoster(
        launcher_id=bytes32(b"\x11" * 32),
        compressed_pubkeys=tuple(
            bytes.fromhex("02" + f"{index + 1:02x}" * 32) for index in range(3)
        ),
    )
    monkeypatch.setattr(
        "solslot_api.admin_operations.resolve_admin_roster", lambda _settings: roster
    )

    app = FastAPI()

    @app.post(
        "/admin/example",
        dependencies=[Depends(require_admin_operation("mint.publish"))],
    )
    async def protected() -> dict[str, bool]:
        return {"ok": True}

    app.dependency_overrides[require_admin_jwt] = lambda: claims()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_operation_store] = lambda: store
    client = TestClient(app)

    assert client.post("/admin/example", json={"value": 7}).status_code == 428
    app.dependency_overrides[require_admin_jwt] = lambda: claims(COADMIN)
    denied = client.post('/admin/example', json={'value': 7},
        headers={'X-Solslot-Admin-Operation-Id': operation_id})
    assert denied.status_code == 403
    assert store.get(operation_id)['status'] == 'approved'
    app.dependency_overrides[require_admin_jwt] = lambda: claims()
    authorized = client.post(
        "/admin/example",
        json={"value": 7},
        headers={"X-Solslot-Admin-Operation-Id": operation_id},
    )
    assert authorized.status_code == 200
    replay = client.post(
        "/admin/example",
        json={"value": 7},
        headers={"X-Solslot-Admin-Operation-Id": operation_id},
    )
    assert replay.status_code == 409


def test_public_typed_data_uses_configured_chain_id(tmp_path) -> None:
    store = OperationStore(tmp_path / "admin.db")
    now = int(time.time())
    binding = canonical_request_binding(
        method="POST", path="/admin/example", query=[], body={}, if_match=None
    )
    operation_id, _ = create_operation(store, binding=binding, now=now)
    value = store.get(operation_id)
    core = AdminOperationCoreV1(
        authority_launcher_id=bytes32(b"\x11" * 32),
        network="testnet11",
        operation=value["operation"],
        payload_hash=bytes32.fromhex(value["payload_hash"].removeprefix("0x")),
        revision=value["revision"],
        nonce=bytes32.fromhex(value["nonce"].removeprefix("0x")),
        expires_at=value["expires_at"],
    )
    public = _public_operation(value, core, chain_id=1)
    assert public["typedData"]["domain"]["chainId"] == 1


def test_http_prepare_sign_and_execute_requires_owner_plus_one(
    tmp_path, monkeypatch
) -> None:
    accounts = tuple(Account.from_key(bytes([index]) * 32) for index in (1, 2, 3))
    roster = AdminRoster(
        launcher_id=bytes32(b"\x11" * 32),
        compressed_pubkeys=tuple(
            eth_keys.PrivateKey(bytes(account.key)).public_key.to_compressed_bytes()
            for account in accounts
        ),
    )
    monkeypatch.setattr(
        "solslot_api.admin_operations.resolve_admin_roster", lambda _settings: roster
    )
    store = OperationStore(tmp_path / "admin.db")
    settings = Settings(
        runtime_environment="test",
        admin_operation_approvals_enabled=True,
        admin_db_path=str(tmp_path / "admin.db"),
        eip712_chain_id=11155111,
    )
    current_subject = {"value": accounts[0].address.lower()}
    app = FastAPI()
    app.include_router(router)

    @app.post(
        "/admin/example",
        dependencies=[Depends(require_admin_operation("mint.cancel"))],
    )
    async def protected() -> dict[str, bool]:
        return {"ok": True}

    app.dependency_overrides[require_admin_jwt] = lambda: claims(
        current_subject["value"]
    )
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_operation_store] = lambda: store
    client = TestClient(app)
    prepared = client.post(
        "/admin/auth/operations/prepare",
        json={
            "operation": "mint.cancel",
            "revision": 0,
            "requestBinding": {
                "method": "POST",
                "path": "/admin/example",
                "query": [],
                "body": {"value": 7},
            },
        },
    )
    assert prepared.status_code == 201
    operation = prepared.json()
    assert operation["typedData"]["domain"]["chainId"] == 11155111
    inbox = client.get("/admin/auth/operations")
    assert inbox.status_code == 200
    assert inbox.json()["count"] == 1
    assert inbox.json()["operations"][0]["operationId"] == operation["operationId"]
    assert inbox.json()["operations"][0]["createdBy"] == accounts[0].address.lower()

    for index in (0, 1):
        current_subject["value"] = accounts[index].address.lower()
        signature = accounts[index].sign_message(
            encode_typed_data(full_message=operation["typedData"])
        ).signature
        signed = client.post(
            f"/admin/auth/operations/{operation['operationId']}/sign",
            json={"signature": "0x" + signature.hex()},
        )
        assert signed.status_code == 200
        operation = signed.json()
        assert operation["status"] == ("pending" if index == 0 else "approved")

    current_subject["value"] = accounts[0].address.lower()
    executed = client.post(
        "/admin/example",
        json={"value": 7},
        headers={"X-Solslot-Admin-Operation-Id": operation["operationId"]},
    )
    assert executed.status_code == 200
    assert client.get(
        f"/admin/auth/operations/{operation['operationId']}"
    ).json()["status"] == "consumed"
    assert client.get("/admin/auth/operations").json()["count"] == 0
    assert (
        client.get(
            "/admin/auth/operations", params={"status_filter": "consumed"}
        ).json()["count"]
        == 1
    )


@pytest.mark.parametrize('coadmin_slot', [1, 2])
def test_mint_requires_matching_http_and_chain_approvals(tmp_path, monkeypatch, coadmin_slot):
    from types import SimpleNamespace
    from solslot_api import admin_operations as operations
    accounts = tuple(Account.from_key(bytes([index])*32) for index in (61, 62, 63))
    roster = AdminRoster(launcher_id=bytes32(b'\x11'*32), compressed_pubkeys=tuple(
        eth_keys.PrivateKey(bytes(account.key)).public_key.to_compressed_bytes() for account in accounts))
    monkeypatch.setattr(operations, 'resolve_admin_roster', lambda _: roster)
    class Action:
        def __init__(self, slot):
            self.action_id = '0x'+bytes([slot+10]).hex()*32
            self.message_hash = '0x'+bytes([slot+20]).hex()*32
            self.signer_public_key = '0x'+roster.compressed_pubkeys[slot].hex()
        def to_wire(self, *, signed):
            return {'actionId': self.action_id, 'signed': signed}
    actions = [Action(slot) for slot in range(3)]
    stale = [False]
    async def build(value, request, settings):
        if stale[0]: raise ValueError('mint publication package is stale')
        return SimpleNamespace(actions=actions)
    monkeypatch.setattr(operations, '_mint_build', build)
    store = OperationStore(tmp_path/'admin.db')
    settings = Settings(runtime_environment='test', admin_operation_approvals_enabled=True,
        admin_db_path=str(tmp_path/'admin.db'), eip712_chain_id=11155111)
    subject = [accounts[0].address.lower()]
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_admin_jwt] = lambda: claims(subject[0])
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_operation_store] = lambda: store
    client = TestClient(app)
    response = client.post('/admin/auth/operations/prepare', json={'operation': 'mint.publish', 'revision': 0,
        'requestBinding': {'method': 'POST', 'path': '/admin/committee/propose', 'query': [], 'body': {'exact': 'wallet package'}}})
    assert response.status_code == 201, response.text
    operation = response.json()
    operation_id = operation['operationId']
    for slot in (0, coadmin_slot):
        subject[0] = accounts[slot].address.lower()
        http_sig = accounts[slot].sign_message(encode_typed_data(full_message=operation['typedData'])).signature
        request_body = {'signature': '0x'+http_sig.hex()}
        url = f'/admin/auth/operations/{operation_id}/sign'
        assert client.post(url, json=request_body).status_code == 409
        assert len(store.get(operation_id)['signatures']) == (0 if slot == 0 else 1)
        sig = eth_keys.PrivateKey(bytes(accounts[slot].key)).sign_msg_hash(bytes.fromhex(actions[slot].message_hash[2:]))
        request_body.update(chainActionId=actions[(slot+1)%3].action_id,
            chainSignature='0x'+(sig.r.to_bytes(32,'big')+sig.s.to_bytes(32,'big')).hex())
        assert client.post(url, json=request_body).status_code == 409
        request_body['chainActionId'] = actions[slot].action_id
        signed = client.post(url, json=request_body)
        assert signed.status_code == 200, signed.text
        assert signed.json()['status'] == ('pending' if slot == 0 else 'approved')
    restored = OperationStore(tmp_path/'admin.db').get(operation_id)
    assert len(restored['chain_signatures']) == len(restored['signatures']) == 2
    stale[0] = True
    assert client.get(f'/admin/auth/operations/{operation_id}').status_code == 409
