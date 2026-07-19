import sqlite3
import os
import time

def clear_screen():
    os.system('clear')

def get_row_count(db_path, table_name):
    if not os.path.exists(db_path):
        return 0
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0

def get_latest_transactions(db_path):
    if not os.path.exists(db_path):
        return []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT tx_id, logical_epoch, timestamp_nanos FROM transaction_manifest ORDER BY logical_epoch DESC LIMIT 5")
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        return []

def render_dashboard():
    while True:
        clear_screen()
        print("=====================================================")
        print("         LUMEN NETWORK LEDGER MONITOR                ")
        print("=====================================================\n")
        
        # Monitor Node 8001
        db_8001 = "network_node_8001.db"
        blocks_8001 = get_row_count(db_8001, "transaction_manifest")
        print(f"[🟢] NODE ALPHA (Port 8001) Status: ACTIVE")
        print(f"     └── Total Chained Blocks: {blocks_8001}")
        
        # Monitor Node 8002
        db_8002 = "network_node_8002.db"
        blocks_8002 = get_row_count(db_8002, "transaction_manifest")
        print(f"[🟢] NODE BETA  (Port 8002) Status: ACTIVE")
        print(f"     └── Total Chained Blocks: {blocks_8002}\n")
        
        print("================ LATEST NETWORK BLOCKS ===============")
        recent_txs = get_latest_transactions(db_8001)
        if not recent_txs:
            print("  No transactions recorded yet in node history.")
        for tx in recent_txs:
            print(f"  [Block #{tx[1]}] Tx ID: {tx[0]} | Time: {tx[2]}")
        print("=====================================================")
        print("\nPress Ctrl+C to exit the dashboard monitor.")
        time.sleep(2)

if __name__ == "__main__":
    try:
        render_dashboard()
    except KeyboardInterrupt:
        print("\n[*] Exiting Dashboard.")
