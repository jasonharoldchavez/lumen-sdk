import hmac
import hashlib
import struct
import math
import aiosqlite
from typing import List, Tuple, Dict, Any

class SQLiteLedgerEngine:
    CANONICAL_NAN_BYTES = b'\x7f\xf8\x00\x00\x00\x00\x00\x00'
    CANONICAL_INF_BYTES = b'\x7f\xf0\x00\x00\x00\x00\x00\x00'
    CANONICAL_NEGINF_BYTES = b'\xff\xf0\x00\x00\x00\x00\x00\x00'
    
    # Statefully tracked schema baseline
    SCHEMA_VERSION = 3

    def __init__(self, path: str, key_provider):
        self.path = path
        self.key_provider = key_provider
        self._write_conn = None
        self._read_conn = None
        self._checkpoint_conn = None

    async def initialize(self):
        self._write_conn = await aiosqlite.connect(self.path, timeout=60.0)
        self._read_conn = await aiosqlite.connect(self.path, timeout=30.0)
        self._checkpoint_conn = await aiosqlite.connect(self.path, timeout=60.0)
        
        for conn in (self._write_conn, self._read_conn, self._checkpoint_conn):
            await conn.execute("PRAGMA foreign_keys = ON;")
            await conn.execute("PRAGMA journal_mode=WAL;")
            await conn.execute("PRAGMA synchronous=FULL;")
            await conn.execute("PRAGMA temp_store=MEMORY;")
            await conn.execute("PRAGMA wal_autocheckpoint=0;")
            await conn.execute("PRAGMA busy_timeout=5000;")

        # Run sequential migration pipeline
        await self._run_migrations()

    async def _run_migrations(self):
        async with self._write_conn.execute("PRAGMA user_version;") as cursor:
            row = await cursor.fetchone()
            current_version = row[0] if row else 0

        if current_version > self.SCHEMA_VERSION:
            raise RuntimeError(f"Database schema version {current_version} is newer than SDK version {self.SCHEMA_VERSION}.")

        if current_version < self.SCHEMA_VERSION:
            await self._write_conn.execute("BEGIN IMMEDIATE;")
            try:
                if current_version < 1:
                    # Greenfield instantiation loop
                    await self._write_conn.execute("""
                        CREATE TABLE IF NOT EXISTS transaction_manifest (
                            tx_id TEXT PRIMARY KEY, logical_epoch INTEGER UNIQUE, timestamp_nanos INTEGER,
                            event_count INTEGER, state_count INTEGER, manifest_hash TEXT UNIQUE,
                            manifest_hmac TEXT, key_id TEXT, previous_manifest_hash TEXT, merkle_root_hash TEXT,
                            crypto_algo TEXT, hmac_version TEXT, hash_version TEXT
                        );
                    """)
                    await self._write_conn.execute("""
                        CREATE TABLE IF NOT EXISTS event_journal (
                            tx_id TEXT, timestamp REAL, node TEXT, metric TEXT, version INTEGER, value BLOB,
                            detector_type TEXT, detector_version TEXT, metadata TEXT, parent_hash TEXT,
                            journal_hash TEXT, journal_hmac TEXT, key_id TEXT, sequence_index INTEGER,
                            PRIMARY KEY (tx_id, sequence_index),
                            FOREIGN KEY (tx_id) REFERENCES transaction_manifest(tx_id) ON DELETE CASCADE
                        );
                    """)
                    await self._write_conn.execute("""
                        CREATE TABLE IF NOT EXISTS causal_manifold_journal (
                            tx_id TEXT PRIMARY KEY, timestamp REAL, causal_matrix_blob BLOB, 
                            matrix_rows INTEGER, matrix_cols INTEGER, matrix_dtype TEXT,
                            structural_invariance_index REAL, manifold_hash TEXT, manifold_hmac TEXT, key_id TEXT,
                            FOREIGN KEY (tx_id) REFERENCES transaction_manifest(tx_id) ON DELETE CASCADE
                        );
                    """)
                    await self._write_conn.execute("""
                        CREATE TABLE IF NOT EXISTS detector_state_history (
                            node TEXT, metric TEXT, tx_id TEXT, version INTEGER, starting_version INTEGER,
                            state TEXT, state_hmac TEXT, key_id TEXT,
                            PRIMARY KEY (node, metric, tx_id, version),
                            FOREIGN KEY (tx_id) REFERENCES transaction_manifest(tx_id) ON DELETE CASCADE
                        );
                    """)
                    await self._write_conn.execute("CREATE INDEX IF NOT EXISTS idx_journal_lookup ON event_journal(node, metric, version DESC);")
                
                if current_version == 1:
                    # Schema Evolution Step: Migrate existing v1 to v2 (adding dimension safety keys)
                    await self._write_conn.execute("ALTER TABLE causal_manifold_journal ADD COLUMN matrix_rows INTEGER DEFAULT 0;")
                    await self._write_conn.execute("ALTER TABLE causal_manifold_journal ADD COLUMN matrix_cols INTEGER DEFAULT 0;")
                    await self._write_conn.execute("ALTER TABLE causal_manifold_journal ADD COLUMN matrix_dtype TEXT DEFAULT '>f8';")

                if current_version <= 2 and current_version > 0:
                    # Schema Evolution Step: Migrate to v3 (injecting agility parameters to older systems seamlessly)
                    await self._write_conn.execute("ALTER TABLE transaction_manifest ADD COLUMN crypto_algo TEXT DEFAULT 'SHA256';")
                    await self._write_conn.execute("ALTER TABLE transaction_manifest ADD COLUMN hmac_version TEXT DEFAULT 'v1';")
                    await self._write_conn.execute("ALTER TABLE transaction_manifest ADD COLUMN hash_version TEXT DEFAULT 'v1';")

                await self._write_conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION};")
                await self._write_conn.commit()
            except Exception as e:
                await self._write_conn.rollback()
                raise RuntimeError(f"Critical schema migration cascade failure: {str(e)}")

    async def get_last_manifest_metadata(self) -> Tuple[int, str]:
        async with self._read_conn.execute("SELECT logical_epoch, manifest_hash FROM transaction_manifest ORDER BY logical_epoch DESC LIMIT 1") as cursor:
            row = await cursor.fetchone()
            return (row[0], row[1]) if row else (0, b"lumen.compliance.ledger.genesis.v1".hex())

    async def get_last_journal_hash(self, node: str, metric: str) -> str:
        async with self._read_conn.execute(
            "SELECT journal_hash FROM event_journal WHERE node=? AND metric=? ORDER BY version DESC LIMIT 1", 
            (node, metric)
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else "0000000000000000000000000000000000000000000000000000000000000000"

    async def execute_passive_checkpoint_get_frames(self) -> int:
        async with self._checkpoint_conn.execute("PRAGMA wal_checkpoint(PASSIVE);") as cursor:
            row = await cursor.fetchone()
            return row[1] if row else 0

    def canonicalize_float_to_bytes(self, val: float) -> bytes:
        if math.isnan(val): return self.CANONICAL_NAN_BYTES
        if math.isinf(val): return self.CANONICAL_INF_BYTES if val > 0 else self.CANONICAL_NEGINF_BYTES
        return struct.pack('>d', val)

    def sign_manifest(self, tx_id: str, epoch: int, nanos: int, ev_count: int, st_count: int, prev_m_hash: str, key_id: str, merkle_root: str, algo: str, hmac_v: str, hash_v: str) -> Tuple[str, str]:
        raw_hash_string = f"{tx_id}:{epoch}:{nanos}:{ev_count}:{st_count}:{prev_m_hash}:{merkle_root}:{algo}:{hmac_v}:{hash_v}"
        m_hash = hashlib.sha256(raw_hash_string.encode()).hexdigest()
        m_hmac = hmac.new(self.key_provider.get_key_material(key_id), m_hash.encode(), hashlib.sha256).hexdigest()
        return m_hash, m_hmac

    def sign_journal_envelope(self, tx_id: str, epoch: int, seq_idx: int, ts: float, node: str, metric: str, ver: int, val_bytes: bytes, det_type: str, det_ver: str, meta_str: str, parent_hash: str, current_hash: str, manifest_hmac: str, key_id: str) -> str:
        base_envelope = f"{tx_id}:{epoch}:{seq_idx}:{ts}:{node}:{metric}:{ver}:{det_type}:{det_ver}:{meta_str}:{parent_hash}:{current_hash}:{manifest_hmac}".encode()
        payload = base_envelope + val_bytes
        return hmac.new(self.key_provider.get_key_material(key_id), payload, hashlib.sha256).hexdigest()

    def sign_manifold_envelope(self, tx_id: str, ts: float, matrix_blob: bytes, rows: int, cols: int, dtype: str, index: float, manifest_hmac: str, key_id: str) -> Tuple[str, str]:
        base_payload = f"{tx_id}:{ts}:{rows}:{cols}:{dtype}:{self.canonicalize_float_to_bytes(index).hex()}:{manifest_hmac}".encode()
        raw_bytes = base_payload + matrix_blob
        m_hash = hashlib.sha256(raw_bytes).hexdigest()
        m_hmac = hmac.new(self.key_provider.get_key_material(key_id), m_hash.encode(), hashlib.sha256).hexdigest()
        return m_hash, m_hmac

    def sign_state_envelope(self, tx_id: str, node: str, metric: str, ver: int, start_ver: int, state_str: str, key_id: str) -> str:
        raw_str = f"{tx_id}:{node}:{metric}:{ver}:{start_ver}:{state_str}"
        return hmac.new(self.key_provider.get_key_material(key_id), raw_str.encode(), hashlib.sha256).hexdigest()

    async def save_compliance_batch_explicit(self, tx_id: str, epoch: int, nanos: int, event_count: int, state_count: int, m_hash: str, m_hmac: str, key_id: str, prev_m_hash: str, merkle_root: str, journal_rows: list, manifold_rows: list, state_rows: list, algo: str = "SHA256", hmac_v: str = "v1", hash_v: str = "v1"):
        await self._write_conn.execute("BEGIN IMMEDIATE;")
        try:
            await self._write_conn.execute(
                "INSERT INTO transaction_manifest VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                (tx_id, epoch, nanos, event_count, state_count, m_hash, m_hmac, key_id, prev_m_hash, merkle_root, algo, hmac_v, hash_v)
            )
            if journal_rows:
                await self._write_conn.executemany("INSERT INTO event_journal VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", journal_rows)
            if manifold_rows:
                await self._write_conn.executemany("INSERT INTO causal_manifold_journal VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", manifold_rows)
            if state_rows:
                await self._write_conn.executemany("INSERT INTO detector_state_history VALUES (?, ?, ?, ?, ?, ?, ?, ?)", state_rows)
            await self._write_conn.commit()
        except Exception as e:
            await self._write_conn.rollback()
            raise e

    async def close(self):
        if self._write_conn: await self._write_conn.close()
        if self._read_conn: await self._read_conn.close()
        if self._checkpoint_conn: await self._checkpoint_conn.close()
