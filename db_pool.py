# db_pool.py
import sqlite3
from queue import Queue
import threading

class DatabasePool:
    def __init__(self, max_connections=10):
        self.max_connections = max_connections
        self.pool = Queue(max_connections)
        self.lock = threading.Lock()
        
        for _ in range(max_connections):
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")  # Better concurrency
            conn.execute("PRAGMA synchronous=NORMAL")  # Balance safety and speed
            self.pool.put(conn)
    
    def get_connection(self):
        return self.pool.get()
    
    def return_connection(self, conn):
        self.pool.put(conn)
    
    def close_all(self):
        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                conn.close()
            except:
                pass

# Global connection pool
db_pool = DatabasePool()

@contextmanager
def get_db_connection():
    conn = db_pool.get_connection()
    try:
        yield conn
    finally:
        db_pool.return_connection(conn)