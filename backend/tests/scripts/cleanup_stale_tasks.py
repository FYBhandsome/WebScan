import sqlite3

db_path = 'D:/AI_WebSecurity/data/webscan.db'
conn = sqlite3.connect(db_path)
cur = conn.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in cur.fetchall()]

for table_name in ['tasks', 'agent_tasks']:
    if table_name in tables:
        cur.execute(f"UPDATE {table_name} SET status='failed', error_message='Interrupted by server restart' WHERE status IN ('pending','running','queued')")
        conn.commit()
        print(f"Updated {cur.rowcount} stale tasks in {table_name}")

conn.close()
print("Done!")