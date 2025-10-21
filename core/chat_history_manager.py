#!/usr/bin/env python3
"""
Chat History Manager
Manages storage and retrieval of AI chat conversations and investigation reports
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.storage_config import resolve_path

logger = logging.getLogger(__name__)


@dataclass
class ChatMessage:
    """Individual chat message"""

    id: str
    conversation_id: str
    role: str  # 'user' or 'assistant'
    content: str
    timestamp: str
    metadata: Dict[str, Any]


@dataclass
class Conversation:
    """Chat conversation"""

    id: str
    investigation_id: Optional[str]
    title: str
    created_at: str
    updated_at: str
    messages: List[ChatMessage]
    metadata: Dict[str, Any]


class ChatHistoryManager:
    """
    Manages chat history storage with SQLite backend
    Supports investigation-linked conversations
    """

    def __init__(self, storage_path: Optional[str] = None):
        """Initialize chat history manager"""
        base_path = Path(storage_path) if storage_path else resolve_path("chat_history")
        base_path.mkdir(exist_ok=True, parents=True)

        self.storage_path = base_path
        self.db_path = self.storage_path / "chat_history.db"
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Conversations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                investigation_id TEXT,
                title TEXT,
                created_at TEXT,
                updated_at TEXT,
                metadata TEXT
            )
        """)

        # Messages table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT,
                role TEXT,
                content TEXT,
                timestamp TEXT,
                metadata TEXT,
                FOREIGN KEY (conversation_id) REFERENCES conversations (id)
            )
        """)

        # Create indexes
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_conversation_investigation 
            ON conversations(investigation_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_message_conversation 
            ON messages(conversation_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_message_timestamp 
            ON messages(timestamp)
        """)

        conn.commit()
        conn.close()

    def create_conversation(
        self,
        investigation_id: Optional[str] = None,
        title: str = "New Conversation",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create a new conversation"""
        conversation_id = f"conv_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        now = datetime.now().isoformat()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO conversations (id, investigation_id, title, created_at, updated_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                conversation_id,
                investigation_id,
                title,
                now,
                now,
                json.dumps(metadata or {}),
            ),
        )

        conn.commit()
        conn.close()

        logger.info(f"Created conversation: {conversation_id}")
        return conversation_id

    def add_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Add a message to a conversation"""
        message_id = f"msg_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        now = datetime.now().isoformat()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Add message
        cursor.execute(
            """
            INSERT INTO messages (id, conversation_id, role, content, timestamp, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                message_id,
                conversation_id,
                role,
                content,
                now,
                json.dumps(metadata or {}),
            ),
        )

        # Update conversation timestamp
        cursor.execute(
            """
            UPDATE conversations SET updated_at = ? WHERE id = ?
        """,
            (now, conversation_id),
        )

        conn.commit()
        conn.close()

        logger.info(f"Added message {message_id} to conversation {conversation_id}")
        return message_id

    def get_conversation(self, conversation_id: str) -> Optional[Conversation]:
        """Get a conversation with all messages"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get conversation
        cursor.execute(
            """
            SELECT id, investigation_id, title, created_at, updated_at, metadata
            FROM conversations WHERE id = ?
        """,
            (conversation_id,),
        )

        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        conv_id, inv_id, title, created, updated, metadata = row

        # Get messages
        cursor.execute(
            """
            SELECT id, conversation_id, role, content, timestamp, metadata
            FROM messages WHERE conversation_id = ?
            ORDER BY timestamp ASC
        """,
            (conversation_id,),
        )

        messages = []
        for msg_row in cursor.fetchall():
            msg_id, conv_id, role, content, timestamp, msg_metadata = msg_row
            messages.append(
                ChatMessage(
                    id=msg_id,
                    conversation_id=conv_id,
                    role=role,
                    content=content,
                    timestamp=timestamp,
                    metadata=json.loads(msg_metadata),
                )
            )

        conn.close()

        return Conversation(
            id=conv_id,
            investigation_id=inv_id,
            title=title,
            created_at=created,
            updated_at=updated,
            messages=messages,
            metadata=json.loads(metadata),
        )

    def list_conversations(
        self, investigation_id: Optional[str] = None, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List conversations, optionally filtered by investigation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if investigation_id:
            cursor.execute(
                """
                SELECT id, investigation_id, title, created_at, updated_at, metadata
                FROM conversations WHERE investigation_id = ?
                ORDER BY updated_at DESC
                LIMIT ? OFFSET ?
            """,
                (investigation_id, limit, offset),
            )
        else:
            cursor.execute(
                """
                SELECT id, investigation_id, title, created_at, updated_at, metadata
                FROM conversations
                ORDER BY updated_at DESC
                LIMIT ? OFFSET ?
            """,
                (limit, offset),
            )

        conversations = []
        for row in cursor.fetchall():
            conv_id, inv_id, title, created, updated, metadata = row

            # Get message count
            cursor.execute(
                """
                SELECT COUNT(*) FROM messages WHERE conversation_id = ?
            """,
                (conv_id,),
            )
            message_count = cursor.fetchone()[0]

            conversations.append(
                {
                    "id": conv_id,
                    "investigation_id": inv_id,
                    "title": title,
                    "created_at": created,
                    "updated_at": updated,
                    "message_count": message_count,
                    "metadata": json.loads(metadata),
                }
            )

        conn.close()
        return conversations

    def delete_conversation(self, conversation_id: str) -> bool:
        """Delete a conversation and all its messages"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Delete messages first
        cursor.execute(
            "DELETE FROM messages WHERE conversation_id = ?", (conversation_id,)
        )

        # Delete conversation
        cursor.execute("DELETE FROM conversations WHERE id = ?", (conversation_id,))

        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()

        if deleted:
            logger.info(f"Deleted conversation: {conversation_id}")

        return deleted

    def search_messages(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Search messages by content"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        def escape_like_pattern(s: str) -> str:
            # Escape %, _, and \ for LIKE patterns
            return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

        escaped_query = escape_like_pattern(query)

        cursor.execute(
            """
            SELECT m.id, m.conversation_id, m.role, m.content, m.timestamp, m.metadata,
                   c.title, c.investigation_id
            FROM messages m
            JOIN conversations c ON m.conversation_id = c.id
            WHERE m.content LIKE ? ESCAPE '\\'
            ORDER BY m.timestamp DESC
            LIMIT ?
        """,
            (f"%{escaped_query}%", limit),
        )

        results = []
        for row in cursor.fetchall():
            msg_id, conv_id, role, content, timestamp, metadata, title, inv_id = row
            results.append(
                {
                    "message_id": msg_id,
                    "conversation_id": conv_id,
                    "conversation_title": title,
                    "investigation_id": inv_id,
                    "role": role,
                    "content": content,
                    "timestamp": timestamp,
                    "metadata": json.loads(metadata),
                }
            )

        conn.close()
        return results

    def export_conversation(
        self, conversation_id: str, format: str = "json"
    ) -> Optional[str]:
        """Export conversation to file"""
        conversation = self.get_conversation(conversation_id)
        if not conversation:
            return None

        export_dir = self.storage_path / "exports"
        export_dir.mkdir(exist_ok=True)

        if format == "json":
            filename = (
                f"{conversation_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            filepath = export_dir / filename

            with open(filepath, "w") as f:
                json.dump(
                    {
                        "conversation": {
                            "id": conversation.id,
                            "investigation_id": conversation.investigation_id,
                            "title": conversation.title,
                            "created_at": conversation.created_at,
                            "updated_at": conversation.updated_at,
                            "metadata": conversation.metadata,
                        },
                        "messages": [asdict(msg) for msg in conversation.messages],
                    },
                    f,
                    indent=2,
                )

            return str(filepath)

        elif format == "markdown":
            filename = (
                f"{conversation_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            )
            filepath = export_dir / filename

            with open(filepath, "w") as f:
                f.write(f"# {conversation.title}\n\n")
                f.write(f"**Conversation ID:** {conversation.id}\n")
                if conversation.investigation_id:
                    f.write(f"**Investigation ID:** {conversation.investigation_id}\n")
                f.write(f"**Created:** {conversation.created_at}\n")
                f.write(f"**Updated:** {conversation.updated_at}\n\n")
                f.write("---\n\n")

                for msg in conversation.messages:
                    role_label = "**User:**" if msg.role == "user" else "**Assistant:**"
                    f.write(f"{role_label} {msg.content}\n\n")
                    f.write(f"*{msg.timestamp}*\n\n")

            return str(filepath)

        return None

    def get_stats(self) -> Dict[str, Any]:
        """Get chat history statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Total conversations
        cursor.execute("SELECT COUNT(*) FROM conversations")
        total_conversations = cursor.fetchone()[0]

        # Total messages
        cursor.execute("SELECT COUNT(*) FROM messages")
        total_messages = cursor.fetchone()[0]

        # Conversations by investigation
        cursor.execute("""
            SELECT investigation_id, COUNT(*) 
            FROM conversations 
            WHERE investigation_id IS NOT NULL
            GROUP BY investigation_id
        """)
        by_investigation = {row[0]: row[1] for row in cursor.fetchall()}

        conn.close()

        return {
            "total_conversations": total_conversations,
            "total_messages": total_messages,
            "conversations_by_investigation": by_investigation,
            "storage_path": str(self.storage_path),
        }


# Example usage
if __name__ == "__main__":
    manager = ChatHistoryManager()

    # Create a conversation
    conv_id = manager.create_conversation(
        investigation_id="inv_123", title="Example Investigation Chat"
    )

    # Add messages
    manager.add_message(conv_id, "user", "Investigate example.com")
    manager.add_message(
        conv_id, "assistant", "Starting investigation on example.com..."
    )

    # Get conversation
    conversation = manager.get_conversation(conv_id)
    print(f"Conversation: {conversation.title}")
    print(f"Messages: {len(conversation.messages)}")

    # List conversations
    conversations = manager.list_conversations()
    print(f"\nTotal conversations: {len(conversations)}")

    # Get stats
    stats = manager.get_stats()
    print(f"\nStats: {stats}")
