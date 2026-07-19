import asyncio
import numpy as np
import sys
import os
import time
import hashlib
import json

sys.path.insert(0,"core")

from sqlite_engine import SQLiteLedgerEngine
from verifier import ForensicAuditVerifier
from merkle import MerkleTreeEngine


class KeyProvider:
    def get_key_material(self,key_id):
        return b"lumen-test-secret-key"


async def run():

    db="nasa_telemetry_test.db"

    if os.path.exists(db):
        os.remove(db)

    engine=SQLiteLedgerEngine(db,KeyProvider())
    await engine.initialize()


    data=np.load(
        os.path.expanduser(
        "~/quantum_simulation_safe/telemanom/data/data/test/A-1.npy"
        )
    )

    if data.ndim>1:
        data=data[:,0]


    print("NASA samples:",len(data))


    tx_id="NASA_A1_TEST"
    epoch=1
    key_id="test"

    journal=[]
    leaves=[]

    previous_hash=await engine.get_last_journal_hash(
        "NASA-A1",
        "telemetry"
    )


    for i,value in enumerate(data[:100]):

        raw_hash=f"{tx_id}:{epoch}:{i}:{value}:{previous_hash}"

        current_hash=hashlib.sha256(
            raw_hash.encode()
        ).hexdigest()


        journal.append([
            tx_id,
            time.time(),
            "NASA-A1",
            "telemetry",
            i,
            engine.canonicalize_float_to_bytes(float(value)),
            "NASA_TELEMETRY",
            "v1",
            json.dumps({
                "source":"Telemanom",
                "channel":"A-1"
            }),
            previous_hash,
            current_hash,
            "",
            key_id,
            i
        ])

        leaves.append(current_hash)

        previous_hash=current_hash


    merkle_root=MerkleTreeEngine.compute_root(leaves)

    manifest_time=time.time_ns()


    m_hash,m_hmac=engine.sign_manifest(
        tx_id,
        epoch,
        manifest_time,
        len(journal),
        0,
        (await engine.get_last_manifest_metadata())[1],
        key_id,
        merkle_root,
        "SHA256",
        "v1",
        "v1"
    )


    fixed=[]

    for row in journal:

        seal=engine.sign_journal_envelope(
            tx_id,
            epoch,
            row[13],
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
            row[6],
            row[7],
            row[8],
            row[9],
            row[10],
            m_hmac,
            key_id
        )

        row[11]=seal
        fixed.append(tuple(row))


    await engine.save_compliance_batch_explicit(
        tx_id,
        epoch,
        manifest_time,
        len(fixed),
        0,
        m_hash,
        m_hmac,
        key_id,
        (await engine.get_last_manifest_metadata())[1],
        merkle_root,
        fixed,
        [],
        []
    )


    verifier=ForensicAuditVerifier(engine)

    result=await verifier.verify_complete_ledger_chain()

    print("\nNASA CLEAN AUDIT")
    print(result)

    await engine.close()


if __name__=="__main__":
    asyncio.run(run())
