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

### 4.1 Technical Part: How to map them into the messages:

Below is a code sample that can be followed:

```go
// API: GET /api/conversations/{id}/messages

func GetMessages(conversationID string, limit int) ([]Message, error) {
    // 1. Fetch messages from MongoDB
    messages := fetchFromMongoDB(conversationID, limit)
    // Returns: [
    //   { message_id: "msg1", content: "Check this!", media_ids: ["media-123", "media-456"] },
    //   { message_id: "msg2", content: "Hi", media_ids: [] }
    // ]

    // 2. Collect all media_ids from all messages
    var allMediaIDs []string
    for _, msg := range messages {
        allMediaIDs = append(allMediaIDs, msg.MediaIDs...)
    }
    // allMediaIDs = ["media-123", "media-456"]

    // 3. Batch fetch media metadata from PostgreSQL (single query!)
    mediaMap := fetchMediaMetadata(allMediaIDs)
    // Returns: {
    //   "media-123": { cdn_url: "https://cdn.../photo.jpg", mime_type: "image/jpeg", ... },
    //   "media-456": { cdn_url: "https://cdn.../video.mp4", mime_type: "video/mp4", ... }
    // }

    // 4. Enrich messages with media metadata
    for i := range messages {
        messages[i].Media = []MediaFile{}
        for _, mediaID := range messages[i].MediaIDs {
            if media, ok := mediaMap[mediaID]; ok {
                messages[i].Media = append(messages[i].Media, media)
            }
        }
    }

    return messages, nil
}
```

Sample response to client:

```json
{
  "messages": [
    {
      "message_id": "msg1",
      "content": "Check this!",
      "media": [
        {
          "media_id": "media-123",
          "cdn_url": "https://cdn.example.com/photo.jpg",
          "mime_type": "image/jpeg",
          "file_size": 204800,
          "metadata": { "width": 1920, "height": 1080, "thumbnail": "..." }
        },
        {
          "media_id": "media-456",
          "cdn_url": "https://cdn.example.com/video.mp4",
          "mime_type": "video/mp4",
          "file_size": 5242880,
          "metadata": { "duration": 15, "thumbnail": "..." }
        }
      ],
      "created_at": "2026-01-15T10:30:00Z"
    },
    {
      "message_id": "msg2",
      "content": "Hi",
      "media": [],
      "created_at": "2026-01-15T10:31:00Z"
    }
  ]
}
```

### 4.1 Forwarding Flow

**Scenario: Alice forwards Bob's photo to Charlie**

```json
Original message (Bob → Alice):
{
  message_id: "msg-123",
  sender_id: "bob",
  content: "Check out my cat!",
  media_ids: ["media-456"]
}

Alice clicks "Forward" → Selects Charlie's chat
```

**What Happens**
**Client-side (Alice's app):**

```json
// Alice already has the full message object in memory
const originalMessage = {
  message_id: "msg-123",
  content: "Check out my cat!",
  media: [
    {
      media_id: "media-456",
      cdn_url: "https://cdn.../cat.jpg",
      mime_type: "image/jpeg",
      // ... all metadata already fetched from Pattern 1
    }
  ]
}

// Forward action
POST /api/messages/forward
{
  original_message_id: "msg-123",  // Optional: track forward chain
  target_conversation_id: "alice-charlie-conv",
  content: "Check out my cat!",  // Can modify
  media_ids: ["media-456"]  // ← Just reuse the same media_id!
}
```

**Server side:**

```go
func ForwardMessage(req ForwardRequest) error {
    // 1. Validate user has access to original message
    originalMsg := mongodb.FindMessage(req.OriginalMessageID)
    if !userCanAccessConversation(currentUser, originalMsg.ConversationID) {
        return errors.New("unauthorized")
    }

    // 2. Validate user can send to target conversation
    if !userCanSendTo(currentUser, req.TargetConversationID) {
        return errors.New("unauthorized")
    }

    // 3. Validate media_ids exist and user has access
    for _, mediaID := range req.MediaIDs {
        media := postgres.Query(`
            SELECT uploaded_by FROM media_files WHERE media_id = $1
        `, mediaID)

        // Check if user can access this media
        // (either uploader or member of conversation where it was shared)
        if !userCanAccessMedia(currentUser, media) {
            return errors.New("cannot forward this media")
        }
    }

    // 4. Create new message in MongoDB
    newMessage := Message{
        MessageID:      uuid.New(),
        ConversationID: req.TargetConversationID,
        SenderID:       currentUser.ID,
        Content:        req.Content,
        MediaIDs:       req.MediaIDs,  // ← Same media_ids, no duplication!
        Metadata: {
            "forwarded_from": req.OriginalMessageID,  // Track forward chain
        },
        CreatedAt:      time.Now(),
    }
    mongodb.Insert(newMessage)

    // 5. Increment reference count (important!)
    postgres.Exec(`
        UPDATE media_files
        SET reference_count = reference_count + 1
        WHERE media_id = ANY($1)
    `, req.MediaIDs)

    // 6. Real-time delivery (Redis pub/sub, etc.)
    publishToConversation(req.TargetConversationID, newMessage)

    return nil
}
```

#### Key points

```
Original message:  media_ids: ["media-456"]
Forwarded message: media_ids: ["media-456"]  ← Same ID!
No new file uploaded! Same file, same CDN URL, just referenced by 2 messages now.
```
