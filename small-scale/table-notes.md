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

## 2. MESSAGE_DELIVERIES_MONGO ( Analytis Focused, This is optional for now )

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

---

## 4. MEDIA_FILES (PostgreSQL)

**Purpose**: Metadata registry for all uploaded files (images, videos, documents, audio). Actual files stored in Aliyun OSS.

**Schema**:

```sql
CREATE TABLE media_files (
    media_id UUID PRIMARY KEY,
    uploaded_by UUID REFERENCES users(user_id),
    file_name VARCHAR(255),               -- "vacation_photo.jpg"
    file_path VARCHAR(500),               -- "uploads/2026/01/abc123.jpg"
    cdn_url VARCHAR(500),                 -- "https://cdn.example.com/abc123.jpg"
    media_type VARCHAR(20),               -- image|video|audio|document
    file_size BIGINT,                     -- bytes
    mime_type VARCHAR(100),               -- "image/jpeg"
    metadata JSONB,                       -- {"width": 1920, "height": 1080, "thumbnail": "..."}
    checksum VARCHAR(100),                -- "sha256:abc123..." for deduplication
    uploaded_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,                 -- null = permanent, set for temp files
    reference_count INT DEFAULT 0         -- How many messages use this file
);

CREATE INDEX idx_media_checksum ON media_files(checksum);
CREATE INDEX idx_media_uploader ON media_files(uploaded_by, uploaded_at DESC);
```

**Architecture**:

```
Actual File (binary) → Aliyun OSS (object storage)
Metadata (info)      → PostgreSQL MEDIA_FILES table
References           → MongoDB messages { media_ids: ["uuid"] }
```

**Upload Flow**:

1. Client uploads file → Server validates
2. Server generates unique filename → Uploads to OSS
3. Get CDN URL, calculate checksum, extract metadata
4. INSERT into MEDIA_FILES table → Return media_id
5. Client sends message with `media_ids: ["media-uuid-123"]`

**Retrieval Flow**:

1. Client loads messages from MongoDB (contains media_ids)
2. Client queries: `GET /api/media?ids=uuid1,uuid2`
3. Server queries MEDIA_FILES → Returns CDN URLs and metadata
4. Client displays using CDN URLs

**Common Queries**:

```sql
-- Get media metadata for message
SELECT media_id, cdn_url, mime_type, metadata
FROM media_files
WHERE media_id = ANY(ARRAY['uuid1', 'uuid2']);

-- Check for duplicate (deduplication)
SELECT media_id, cdn_url
FROM media_files
WHERE checksum = 'sha256:abc123...'
  AND uploaded_by = 'user-id';

-- Cleanup expired temp files
SELECT media_id, file_path
FROM media_files
WHERE expires_at < NOW()
  AND reference_count = 0;

-- User's media library
SELECT media_id, file_name, cdn_url, uploaded_at
FROM media_files
WHERE uploaded_by = 'user-id'
ORDER BY uploaded_at DESC;
```

**Reference Counting**:

```javascript
// Message created with media
INSERT INTO media_files (..., reference_count = 1)

// Message references existing media
UPDATE media_files
SET reference_count = reference_count + 1
WHERE media_id = 'abc123'

// Message deleted
UPDATE media_files
SET reference_count = reference_count - 1
WHERE media_id = 'abc123'

// Garbage collection job
DELETE FROM media_files
WHERE reference_count = 0
  AND uploaded_at < NOW() - INTERVAL '30 days'
```

**Deduplication Example**:

```
User uploads cat.jpg to 3 different chats:

1. Upload → OSS stores 1 file (uuid-abc.jpg)
   PostgreSQL: INSERT (media_id: uuid-abc, reference_count: 0)

2. Send to Chat A
   MongoDB: { media_ids: ["uuid-abc"] }
   PostgreSQL: reference_count = 1

3. Send to Chat B (checksum match!)
   MongoDB: { media_ids: ["uuid-abc"] } (reuse)
   PostgreSQL: reference_count = 2

4. Send to Chat C
   MongoDB: { media_ids: ["uuid-abc"] }
   PostgreSQL: reference_count = 3

Result: 1 file in OSS instead of 3 (66% storage savings)
```

**Key Benefits**:

- **Access Control**: Verify user permissions before serving files
- **Deduplication**: Same file uploaded multiple times = stored once
- **Cleanup**: Track references, delete orphaned files
- **Analytics**: Query total storage, popular file types
- **Metadata**: Store dimensions, thumbnails, processed versions in JSONB

**Why PostgreSQL?** Need structured queries (user's media, deduplication), access control joins, ACID guarantees for reference counting, efficient indexing on checksum/uploader.

**Why Separate from MongoDB Messages?** Single source of truth, no metadata duplication, cross-conversation queries, proper garbage collection.

---

## Quick Reference

| Table              | Storage    | Volume | Primary Use Case               |
| ------------------ | ---------- | ------ | ------------------------------ |
| MESSAGE_REACTIONS  | MongoDB    | 100M+  | Display "❤️ 23" counts         |
| MESSAGE_DELIVERIES | MongoDB    | 1B+    | Track/retry push notifications |
| MENTIONS           | PostgreSQL | 10M+   | "5 unread mentions" badge      |
| MEDIA_FILES        | PostgreSQL | 50M+   | File metadata & deduplication  |
