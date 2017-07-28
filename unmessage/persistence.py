import errno
import sqlite3

import attr
from pyaxo import Keypair, a2b, b2a

from .contact import Contact


@attr.s
class PeerInfo(object):
    name = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(str)),
        default=None)
    port_local_server = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(int)),
        default=None)
    identity_keys = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(Keypair)),
        default=None)
    onion_service_key = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(str)),
        default=None)
    contacts = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(dict)),
        default=attr.Factory(dict))


@attr.s
class Persistence(object):
    dbname = attr.ib(validator=attr.validators.instance_of(str))
    dbpassphrase = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(dict)),
        default=None)
    db = attr.ib(init=False)

    def __attrs_post_init__(self):
        self.db = self._open_db()

    def _open_db(self):
        db = sqlite3.connect(':memory:', check_same_thread=False)
        db.row_factory = sqlite3.Row

        with db:
            try:
                with open(self.dbname, 'r') as f:
                    sql = f.read()
                    db.cursor().executescript(sql)
            except IOError as e:
                if e.errno == errno.ENOENT:
                    self._create_db(db)
                else:
                    raise
        return db

    def _create_db(self, db):
        db.execute('''
            CREATE TABLE IF NOT EXISTS
                peer (
                    name TEXT,
                    port_local_server INTEGER,
                    priv_identity_key TEXT,
                    pub_identity_key TEXT,
                    onion_service_key TEXT)''')
        db.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS
                peer_name
            ON
                peer (name)''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS
                contacts (
                    identity TEXT,
                    key TEXT,
                    is_verified INTEGER,
                    has_presence INTEGER)''')
        db.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS
                contact_identity
            ON
                contacts (identity)''')

    def _write_db(self):
        with self.db as db:
            sql = bytes('\n'.join(db.iterdump()))
            with open(self.dbname, 'w') as f:
                f.write(sql)

    def load_peer_info(self):
        with self.db as db:
            cur = db.cursor()
            cur.execute('''
                SELECT
                    *
                FROM
                    peer''')
            row = cur.fetchone()
        if row:
            onion_service_key = str(row['onion_service_key'])
            identity_keys = Keypair(a2b(row['priv_identity_key']),
                                    a2b(row['pub_identity_key']))
            port_local_server = int(row['port_local_server'])
            name = str(row['name'])
        else:
            onion_service_key = None
            identity_keys = None
            port_local_server = None
            name = None

        with self.db as db:
            rows = db.execute('''
                SELECT
                    *
                FROM
                    contacts''')
        contacts = dict()
        for row in rows:
            c = Contact(str(row['identity']),
                        a2b(row['key']),
                        bool(row['is_verified']),
                        bool(row['has_presence']))
            contacts[c.name] = c

        return PeerInfo(name, port_local_server, identity_keys,
                        onion_service_key, contacts)

    def save_peer_info(self, peer_info):
        with self.db as db:
            db.execute('''
                DELETE FROM
                    peer''')
            if peer_info.identity_keys:
                db.execute('''
                    INSERT INTO
                        peer (
                            name,
                            port_local_server,
                            priv_identity_key,
                            pub_identity_key,
                            onion_service_key)
                    VALUES (?, ?, ?, ?, ?)''', (
                        peer_info.name,
                        peer_info.port_local_server,
                        b2a(peer_info.identity_keys.priv),
                        b2a(peer_info.identity_keys.pub),
                        peer_info.onion_service_key))
            db.execute('''
                DELETE FROM
                    contacts''')
            for c in peer_info.contacts.values():
                db.execute('''
                    INSERT INTO
                        contacts (
                            identity,
                            key,
                            is_verified,
                            has_presence)
                    VALUES (?, ?, ?, ?)''', (
                        c.identity,
                        b2a(c.key),
                        int(c.is_verified),
                        int(c.has_presence)))

        self._write_db()
