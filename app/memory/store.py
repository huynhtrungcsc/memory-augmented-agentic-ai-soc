"""
Memory store factory.

Change the import here to swap memory backends without touching anything else.

MemPalace integration point:
  from app.memory.mempalace_store import MemPalaceStore as MemoryStore
"""

from app.memory.sqlite_store import SQLiteMemoryStore as MemoryStore

__all__ = ["MemoryStore"]
