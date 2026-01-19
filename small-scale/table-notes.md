# Message Feature Tables - Developer Guide

## 1. MESSAGE_REACTIONS_MONGO

**Purpose**: Stores emoji reactions to messages (❤️ 👍 😂 🔥)

**Schema**:

```javascript
{
  _id: ObjectId,
  message_id: ObjectId,
  user_id: "uuid",
  emoji: "❤️",
  created_at: ISODate
}
// Unique index: { message_id: 1, user_id: 1, emoji: 1 }
```

**Common Queries**:

```javascript
// Get reactions with counts
db.message_reactions.aggregate([
  { $match: { message_id: ObjectId("msg_123") } },
  {
    $group: {
      _id: "$emoji",
      count: { $sum: 1 },
      users: { $push: "$user_id" },
    },
  },
]);

// Remove reaction
db.message_reactions.deleteOne({
  message_id: ObjectId("msg_123"),
  user_id: "alice",
  emoji: "❤️",
});
```

**Why MongoDB?** High volume, co-located with messages, flexible schema, no complex joins needed.

---

## 2. MESSAGE_DELIVERIES_MONGO ( No need to do this, this is optional for now )

**Purpose**: Tracks per-user delivery status for each message (critical for push notifications and offline users)

**Schema**:

```javascript
{
  _id: ObjectId,
  message_id: ObjectId,
  user_id: "uuid",
  status: "sent|delivered|failed",
  delivered_at: ISODate,
  error_message: "FCM token expired" // if failed
}
// Index: { message_id: 1, user_id: 1 }
```

**Flow**:

- Online users → WebSocket delivery → status: "delivered"
- Offline users → RabbitMQ + FCM push → status: "delivered" or "failed"
- Failed deliveries → background job retries

**Common Queries**:

```javascript
// Find failed deliveries
db.message_deliveries.find({
  message_id: ObjectId("msg_123"),
  status: "failed",
});

// Retry candidates (failed > 1 hour ago)
db.message_deliveries.find({
  status: "failed",
  delivered_at: { $lt: Date.now() - 3600000 },
});
```

**Why MongoDB?** Billions of records (message × recipients), write-heavy, co-located with messages, TTL indexes for auto-cleanup.

**Key Benefits**: Track delivery status, retry failed notifications, debug "user didn't receive message" issues.

---

## 3. MENTIONS (PostgreSQL)

**Purpose**: Tracks @mentions in messages for notifications and "unread mentions" feature

**Schema**:

```sql
CREATE TABLE mentions (
    mention_id UUID PRIMARY KEY,
    message_id VARCHAR(24),  -- MongoDB ObjectId
    mentioned_user_id UUID REFERENCES users(user_id),
    mentioned_by UUID REFERENCES users(user_id),
    conversation_id UUID REFERENCES conversations(conversation_id),
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    read_at TIMESTAMP
);

CREATE INDEX idx_unread_mentions
    ON mentions(mentioned_user_id, is_read, created_at DESC);
```

**Common Queries**:

```sql
-- Unread mentions count (for badge)
SELECT COUNT(*)
FROM mentions
WHERE mentioned_user_id = 'alice-uuid'
  AND is_read = FALSE;

-- Mentions list with context
SELECT
    m.mention_id,
    m.message_id,
    c.group_name,
    u.display_name AS mentioned_by_name,
    m.created_at
FROM mentions m
JOIN conversations c ON m.conversation_id = c.conversation_id
JOIN users u ON m.mentioned_by = u.user_id
WHERE m.mentioned_user_id = 'alice-uuid'
  AND m.is_read = FALSE
ORDER BY m.created_at DESC;

-- Mark as read
UPDATE mentions
SET is_read = TRUE, read_at = NOW()
WHERE mention_id = 'uuid1';
```

**Processing Flow**:

1. Message saved to MongoDB with `mentions: ["alice-uuid", "charlie-uuid"]`
2. RabbitMQ job detects @mentions and creates MENTIONS records
3. Redis pub/sub notifies users
4. WebSocket + push notifications sent

**Why PostgreSQL?** Need structured queries across conversations, joins with USERS/CONVERSATIONS, ACID guarantees for is_read updates, efficient filtering with indexes.

**Why Separate Table?** Can't efficiently query "all unread mentions across all conversations" if stored in MongoDB messages. Separate table enables single fast query: `WHERE mentioned_user_id = X AND is_read = FALSE`.

---

## Quick Reference

| Table              | Storage    | Volume | Primary Use Case               |
| ------------------ | ---------- | ------ | ------------------------------ |
| MESSAGE_REACTIONS  | MongoDB    | 100M+  | Display "❤️ 23" counts         |
| MESSAGE_DELIVERIES | MongoDB    | 1B+    | Track/retry push notifications |
| MENTIONS           | PostgreSQL | 10M+   | "5 unread mentions" badge      |
