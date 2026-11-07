"""Durable generation-local customer consent and exact funding holds.

No discovery, old-data import, transaction builder, fee selector or broadcast.
Status reads never renew a challenge or ask the wallet to sign again.
"""
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path

from chia_rs.sized_bytes import bytes32

from .generation_context import generation_bytes
from .generation_customer_launch import CustomerLaunchBindings, CustomerLaunchConsent
from .generation_storage import generation_path, connect_generation_sqlite, admit_retained_bytes


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def read_consent(document):
    names = {'generationId', 'preparationManifest', 'network', 'poolLauncherId',
             'bridgePolicyHash', 'vaultModuleHash', 'owner', 'authType', 'fundingCoinId',
             'vaultLauncherId', 'nonce', 'expiresAt', 'purpose'}
    if (not isinstance(document, dict) or set(document) != names
            or document['network'] != 'testnet11'
            or document['purpose'] != 'CREATE_FRESH_CUSTOMER_VAULT_REQUIRES_NEW_ID_CHECK'):
        raise ValueError('one canonical fresh registration consent is required')
    b = bytes32.from_hexstr
    result = CustomerLaunchConsent(CustomerLaunchBindings(b(document['generationId']),
        b(document['preparationManifest']), b(document['poolLauncherId']),
        b(document['bridgePolicyHash']), b(document['vaultModuleHash'])),
        b(document['nonce']), document['owner'], document['authType'],
        b(document['fundingCoinId']), b(document['vaultLauncherId']), document['expiresAt']).validate()
    if result.message() != document:
        raise ValueError('registration consent is not canonical')
    return result


class CustomerRegistrationConflict(ValueError):
    pass


class GenerationCustomerStore:
    MAX_RETAINED_BYTES = 64 * 1024 * 1024

    def __init__(self, path, generation_id):
        generation_bytes(generation_id)
        self.generation_id = '0x' + generation_bytes(generation_id).hex()
        self.path = generation_path(path, generation_id)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        os.close(fd)
        with self._db() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('''CREATE TABLE IF NOT EXISTS customer_registration_consents (
                registration_id TEXT PRIMARY KEY, owner_key TEXT NOT NULL,
                funding_coin_id TEXT NOT NULL, nonce TEXT UNIQUE NOT NULL,
                document TEXT NOT NULL, stage TEXT NOT NULL,
                created_at INTEGER NOT NULL, signature TEXT, authorized_at INTEGER)''')
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS customer_active_owner ON customer_registration_consents(owner_key) WHERE stage IN ('REVIEW_READY','AUTHORIZED')")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS customer_active_funding ON customer_registration_consents(funding_coin_id) WHERE stage IN ('REVIEW_READY','AUTHORIZED')")
            db.execute('''CREATE TABLE IF NOT EXISTS customer_browser_access (
                registration_id TEXT PRIMARY KEY, browser_hash TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS customer_creation_confirmations (
                registration_id TEXT PRIMARY KEY, operation_id TEXT UNIQUE NOT NULL,
                transaction_id TEXT UNIQUE NOT NULL, vault_coin_id TEXT UNIQUE NOT NULL,
                confirmed_height INTEGER NOT NULL CHECK(confirmed_height>0))''')
            db.execute('''CREATE TABLE IF NOT EXISTS customer_vault_observations (
                registration_id TEXT PRIMARY KEY, checked_at INTEGER NOT NULL,
                document TEXT NOT NULL)''')

    @contextmanager
    def _db(self, write=False):
        db = connect_generation_sqlite(self.path, generation_id=self.generation_id,
            timeout=5, isolation_level=None)
        db.row_factory = __import__('sqlite3').Row
        db.execute('PRAGMA synchronous=FULL')
        try:
            if write:
                db.execute('BEGIN IMMEDIATE')
            yield db
            if write:
                db.execute('COMMIT')
        except BaseException:
            if db.in_transaction:
                db.execute('ROLLBACK')
            raise
        finally:
            db.close()

    def _checked(self, row):
        if row is None:
            raise CustomerRegistrationConflict('registration is not present in this generation')
        document = json.loads(row['document'])
        consent = read_consent(document)
        identity = '0x' + sha256(canonical(document).encode()).hexdigest()
        if (document['generationId'] != self.generation_id or identity != row['registration_id']
                or row['funding_coin_id'] != document['fundingCoinId']
                or row['nonce'] != document['nonce']
                or row['owner_key'] != consent.auth_type + ':' + consent.owner.lower()
                or row['stage'] not in ('REVIEW_READY', 'AUTHORIZED', 'EXPIRED_UNSIGNED')
                or (row['stage'] in ('REVIEW_READY', 'EXPIRED_UNSIGNED') and
                    (row['signature'] is not None or row['authorized_at'] is not None))
                or (row['stage'] == 'AUTHORIZED' and
                    (row['signature'] is None or row['authorized_at'] is None))):
            raise CustomerRegistrationConflict('saved registration evidence is inconsistent')
        if row['stage'] == 'AUTHORIZED':
            if type(row['authorized_at']) is not int or row['authorized_at'] < row['created_at']:
                raise CustomerRegistrationConflict('saved authorization predates its review')
            consent.verified_owner(row['signature'], row['authorized_at'])
        return consent

    def _expire_unsigned(self, db, now):
        # Signature acceptance must commit before any native operation can be
        # assembled. These rows therefore have no authorized/signed operation
        # to resume, so their temporary hold can expire without deleting history.
        rows = db.execute("SELECT * FROM customer_registration_consents WHERE stage='REVIEW_READY' AND signature IS NULL AND authorized_at IS NULL").fetchall()
        changed = 0
        for row in rows:
            consent = self._checked(row)
            if now >= consent.expires_at:
                db.execute("UPDATE customer_registration_consents SET stage='EXPIRED_UNSIGNED' WHERE registration_id=? AND stage='REVIEW_READY'", (row['registration_id'],))
                changed += 1
        return changed

    @staticmethod
    def _status(row, consent, now):
        return {'registrationId': row['registration_id'],
            'generationId': consent.message()['generationId'], 'network': 'testnet11',
            'stage': 'CONSENT_EXPIRED' if row['stage'] == 'REVIEW_READY' and now >= consent.expires_at else row['stage'],
            'vaultLauncherId': consent.message()['vaultLauncherId'],
            'signBy': consent.expires_at, 'authorizationSavedAt': row['authorized_at'],
            'review': consent.message(), 'identityVerified': False,
            'registrationConfirmed': False, 'transactionId': None}

    def reserve(self, consent: CustomerLaunchConsent, *, now: int, browser_hash: str | None = None):
        consent.validate()
        if (consent.message()['generationId'] != self.generation_id
                or type(now) is not int or not now < consent.expires_at <= now + 300):
            raise ValueError('reservation requires current generation and a five-minute consent window')
        raw = canonical(consent.message())
        identity = '0x' + sha256(raw.encode()).hexdigest()
        owner = consent.auth_type + ':' + consent.owner.lower()
        if browser_hash is not None:
            self._browser_hash(browser_hash)
        with self._db(write=True) as db:
            self._expire_unsigned(db, now)
            row = db.execute("SELECT * FROM customer_registration_consents WHERE owner_key=? AND stage IN ('REVIEW_READY','AUTHORIZED')", (owner,)).fetchone()
            if row is not None:
                saved = self._checked(row)
                if row['document'] != raw:
                    raise CustomerRegistrationConflict('existing registration must be resumed or reconciled, never silently replaced')
                if browser_hash is not None:
                    self._browser_access(db, identity, browser_hash)
                return self._status(row, saved, now)
            if db.execute("SELECT 1 FROM customer_registration_consents WHERE (funding_coin_id=? AND stage IN ('REVIEW_READY','AUTHORIZED')) OR nonce=?",
                    (consent.message()['fundingCoinId'], consent.message()['nonce'])).fetchone():
                raise CustomerRegistrationConflict('the funding parent or challenge is already held by another registration')
            retained = db.execute('SELECT coalesce(sum(length(document)+coalesce(length(signature),0)),0) FROM customer_registration_consents').fetchone()[0]
            admit_retained_bytes(db, retained, len(raw), self.MAX_RETAINED_BYTES)
            db.execute('INSERT INTO customer_registration_consents VALUES (?,?,?,?,?,?,?,NULL,NULL)',
                (identity, owner, consent.message()['fundingCoinId'], consent.message()['nonce'], raw, 'REVIEW_READY', now))
            if browser_hash is not None:
                db.execute('INSERT INTO customer_browser_access VALUES (?,?)',(identity,browser_hash))
            row = db.execute('SELECT * FROM customer_registration_consents WHERE registration_id=?', (identity,)).fetchone()
            return self._status(row, consent, now)

    @staticmethod
    def _browser_hash(value):
        import re
        if not isinstance(value,str) or re.fullmatch(r'[0-9a-f]{64}',value) is None:
            raise CustomerRegistrationConflict('a current browser continuation is required')

    def _browser_access(self,db,identity,browser_hash):
        import hmac
        self._browser_hash(browser_hash)
        row=db.execute('SELECT browser_hash FROM customer_browser_access WHERE registration_id=?',(identity,)).fetchone()
        if row is None or not hmac.compare_digest(row['browser_hash'],browser_hash):
            raise CustomerRegistrationConflict('this browser cannot access that registration')

    def require_browser(self,identity,browser_hash):
        with self._db() as db:
            self._browser_access(db,identity,browser_hash)

    def active_owner_review(self,owner,auth_type,*,browser_hash,now):
        """A private continuation lookup; no node, signing or write operation."""
        with self._db() as db:
            row=db.execute("SELECT * FROM customer_registration_consents WHERE owner_key=? AND stage IN ('REVIEW_READY','AUTHORIZED')",
                (auth_type+':'+owner.lower(),)).fetchone()
            if row is None:return None
            self._browser_access(db,row['registration_id'],browser_hash)
            return self._status(row,self._checked(row),now)

    def confirm_creation(self,evidence,*,operation_id,transaction_id):
        """Persist evidence obtained by the native verifier, never an HTTP body."""
        from .generation_customer_execution import CustomerCreationEvidence
        import re
        if (not isinstance(evidence,CustomerCreationEvidence) or evidence.generation_id!=self.generation_id
                or evidence.operation_id!=operation_id or type(evidence.confirmed_height) is not int
                or evidence.confirmed_height<=0 or not isinstance(transaction_id,str)
                or re.fullmatch(r'0x[0-9a-f]{64}',transaction_id) is None):
            raise CustomerRegistrationConflict('exact verified native confirmation is required')
        with self._db(write=True) as db:
            row=db.execute('SELECT * FROM customer_registration_consents WHERE registration_id=?',(evidence.registration_id,)).fetchone()
            consent=self._checked(row)
            if row['stage']!='AUTHORIZED' or consent.message()['vaultLauncherId']!=evidence.vault_launcher_id:
                raise CustomerRegistrationConflict('confirmation differs from the signed registration')
            values=(evidence.registration_id,operation_id,transaction_id,evidence.vault_coin_id,evidence.confirmed_height)
            saved=db.execute('SELECT * FROM customer_creation_confirmations WHERE registration_id=?',(evidence.registration_id,)).fetchone()
            if saved is not None:
                if tuple(saved)!=values:raise CustomerRegistrationConflict('saved native confirmation cannot change')
                return
            db.execute('INSERT INTO customer_creation_confirmations VALUES (?,?,?,?,?)',values)

    def confirmation(self,identity):
        with self._db() as db:
            row=db.execute('SELECT * FROM customer_creation_confirmations WHERE registration_id=?',(identity,)).fetchone()
            return dict(row) if row else None

    def confirmed_owner(self,owner,auth_type):
        """Public creation coordinates only. No signature, session or ID receipt."""
        with self._db() as db:
            row=db.execute('''SELECT c.* FROM customer_registration_consents c
                JOIN customer_creation_confirmations v USING(registration_id) WHERE c.owner_key=?''',
                (auth_type+':'+owner.lower(),)).fetchone()
            if row is None:return None
            consent=self._checked(row)
            return {'generationId':self.generation_id,'network':'testnet11',
                'vaultLauncherId':consent.message()['vaultLauncherId'],'authType':consent.auth_type,
                'registrationConfirmed':True,'owner':consent.owner,
                'identityStatus':'CHECK_AFTER_SIGN_IN','requiresOwnerSignIn':True}

    def registered_vault(self, launcher):
        """Only creation-confirmed records in this generation; never import old registries."""
        with self._db() as db:
            rows=db.execute('''SELECT c.* FROM customer_registration_consents c
                JOIN customer_creation_confirmations v USING(registration_id)''').fetchall()
            for row in rows:
                consent=self._checked(row)
                if consent.message()['vaultLauncherId']==launcher:
                    return row['registration_id'],consent
        raise CustomerRegistrationConflict('this vault has no confirmed registration in this generation')

    def confirmed_registrations(self, limit=32):
        if type(limit)is not int or not 1<=limit<=128:
            raise ValueError('bounded customer observation is required')
        with self._db() as db:
            rows=db.execute('''SELECT c.* FROM customer_registration_consents c
                JOIN customer_creation_confirmations v USING(registration_id)
                LEFT JOIN customer_vault_observations o USING(registration_id)
                ORDER BY coalesce(o.checked_at,0),c.created_at LIMIT ?''',(limit,)).fetchall()
            for row in rows:self._checked(row)
            return [row['registration_id'] for row in rows]

    def observe_vault(self, identity, evidence, *, now):
        from .generation_customer_vault import CurrentCustomerVault
        if (not isinstance(evidence,CurrentCustomerVault) or
                '0x'+evidence.generation.hex()!=self.generation_id or type(now)is not int or now<=0):
            raise CustomerRegistrationConflict('native current-generation custody evidence is required')
        with self._db(write=True) as db:
            row=db.execute('SELECT * FROM customer_registration_consents WHERE registration_id=?',(identity,)).fetchone()
            consent=self._checked(row)
            if (consent.message()['vaultLauncherId']!='0x'+evidence.launcher.hex() or
                    not db.execute('SELECT 1 FROM customer_creation_confirmations WHERE registration_id=?',(identity,)).fetchone()):
                raise CustomerRegistrationConflict('observation differs from confirmed registration')
            document=canonical(evidence.public())
            retained=db.execute('''SELECT coalesce(sum(length(document)+coalesce(length(signature),0)),0)
                FROM customer_registration_consents''').fetchone()[0]
            retained+=db.execute('''SELECT coalesce(sum(length(document)),0)
                FROM customer_vault_observations WHERE registration_id!=?''',(identity,)).fetchone()[0]
            admit_retained_bytes(db,retained,len(document),self.MAX_RETAINED_BYTES)
            db.execute('''INSERT INTO customer_vault_observations VALUES (?,?,?)
                ON CONFLICT(registration_id) DO UPDATE SET checked_at=excluded.checked_at,document=excluded.document''',
                (identity,now,document))

    def vault_observation(self,identity):
        with self._db() as db:
            row=db.execute('SELECT * FROM customer_vault_observations WHERE registration_id=?',(identity,)).fetchone()
            return {'checkedAt':row['checked_at'],'vault':json.loads(row['document'])} if row else None

    def pending_authorized(self,limit=32):
        if type(limit) is not int or not 1<=limit<=128:raise ValueError('bounded customer reconciliation is required')
        with self._db() as db:
            rows=db.execute('''SELECT c.* FROM customer_registration_consents c
                LEFT JOIN customer_creation_confirmations v USING(registration_id)
                WHERE c.stage='AUTHORIZED' AND v.registration_id IS NULL ORDER BY c.created_at LIMIT ?''',(limit,)).fetchall()
            for row in rows:self._checked(row)
            return [row['registration_id'] for row in rows]

    def accept_signature(self, identity, signature, *, now: int):
        with self._db(write=True) as db:
            row = db.execute('SELECT * FROM customer_registration_consents WHERE registration_id=?', (identity,)).fetchone()
            consent = self._checked(row)
            if row['stage'] == 'EXPIRED_UNSIGNED':
                raise CustomerRegistrationConflict('this unsigned registration expired; resume the newest review')
            if row['stage'] == 'AUTHORIZED':
                if signature != row['signature']:
                    raise CustomerRegistrationConflict('a saved authorization cannot be overwritten')
                return self._status(row, consent, now)
            consent.verified_owner(signature, now)
            retained = db.execute('SELECT coalesce(sum(length(document)+coalesce(length(signature),0)),0) FROM customer_registration_consents').fetchone()[0]
            admit_retained_bytes(db, retained, len(signature), self.MAX_RETAINED_BYTES)
            db.execute("UPDATE customer_registration_consents SET stage='AUTHORIZED',signature=?,authorized_at=? WHERE registration_id=? AND stage='REVIEW_READY'",
                (signature, now, identity))
            row = db.execute('SELECT * FROM customer_registration_consents WHERE registration_id=?', (identity,)).fetchone()
            return self._status(row, consent, now)

    def status(self, identity, *, now: int):
        with self._db() as db:
            row = db.execute('SELECT * FROM customer_registration_consents WHERE registration_id=?', (identity,)).fetchone()
            return self._status(row, self._checked(row), now)

    def authorized_material(self, identity):
        """Private execution input; never return this from an HTTP/status route."""
        with self._db() as db:
            row = db.execute('SELECT * FROM customer_registration_consents WHERE registration_id=?', (identity,)).fetchone()
            consent = self._checked(row)
            if row['stage'] != 'AUTHORIZED':
                raise CustomerRegistrationConflict('the exact customer consent has not been signed')
            return consent, row['signature'], row['authorized_at']

    def held_funding_ids(self):
        with self._db() as db:
            rows = db.execute("SELECT * FROM customer_registration_consents WHERE stage IN ('REVIEW_READY','AUTHORIZED')").fetchall()
            for row in rows:
                self._checked(row)
            # A saved authorization is never released merely because sign-by
            # passed. It might already have an exact native operation to resume.
            return frozenset(row['funding_coin_id'] for row in rows)

    def expire_unsigned(self, *, now: int):
        if type(now) is not int or now <= 0:
            raise ValueError('expiry reconciliation requires a positive timestamp')
        with self._db(write=True) as db:
            return self._expire_unsigned(db, now)
