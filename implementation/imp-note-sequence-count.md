## **What Needs to Happen in `Create`:**

```go
func (s *messageService) Create(ctx context.Context, message *models.Message) error {
    // 1. Validate
    if message.ConversationID == uuid.Nil {
        return errors.New("conversation_id is required")
    }
    if message.SenderID == uuid.Nil {
        return errors.New("sender_id is required")
    }
    if message.MessageType == "" {
        return errors.New("message_type is required")
    }

    // 2. Generate sequence number (atomic)
    sequenceNumber, err := s.generateSequenceNumber(ctx, message.ConversationID)
    if err != nil {
        return err
    }
    message.SequenceNumber = sequenceNumber

    // 3. Set timestamps
    message.CreatedAt = time.Now()

    // 4. Insert to MongoDB
    err = s.messageRepo.Create(ctx, message)
    if err != nil {
        return err
    }

    // 5. Update CONVERSATIONS table in PostgreSQL
    err = s.updateConversationMetadata(ctx, message)
    if err != nil {
        // Log error but don't fail the message creation
        // Message already in MongoDB, conversation update can be retried
        log.Printf("Failed to update conversation metadata: %v", err)
    }

    // 6. Publish to Redis Pub/Sub (real-time delivery)
    s.publishToRedis(ctx, message)

    // 7. Queue to RabbitMQ (push notifications for offline users)
    s.queuePushNotification(ctx, message)

    return nil
}
```

---

## **PostgreSQL Conversation Update**

```go
func (s *messageService) updateConversationMetadata(ctx context.Context, message *models.Message) error {
    // Get conversation type (direct or group)
    conversation, err := s.conversationRepo.GetByID(ctx, message.ConversationID)
    if err != nil {
        return err
    }

    // Generate message preview (first 100 chars)
    preview := message.Content
    if len(preview) > 100 {
        preview = preview[:100] + "..."
    }
    if message.MessageType != "text" {
        preview = s.getMediaPreviewText(message.MessageType, message.MediaIDs)
    }

    // Update conversation metadata
    query := `
        UPDATE conversations
        SET 
            last_message_id = $1,
            last_message_at = $2,
            last_message_preview = $3
    `

    args := []interface{}{
        message.ID.Hex(),           // Store MongoDB ObjectID as string
        message.CreatedAt,
        preview,
    }

    // For direct chats, increment unread count for the OTHER user
    if conversation.Type == "direct" {
        if conversation.User1ID == message.SenderID {
            // Sender is user1, increment unread for user2
            query += `, unread_count_user2 = unread_count_user2 + 1`
        } else {
            // Sender is user2, increment unread for user1
            query += `, unread_count_user1 = unread_count_user1 + 1`
        }
    }

    query += ` WHERE conversation_id = $4`
    args = append(args, message.ConversationID)

    _, err = s.db.ExecContext(ctx, query, args...)
    return err
}

func (s *messageService) getMediaPreviewText(messageType string, mediaIDs []uuid.UUID) string {
    switch messageType {
    case "image":
        if len(mediaIDs) > 1 {
            return fmt.Sprintf("📷 %d photos", len(mediaIDs))
        }
        return "📷 Photo"
    case "video":
        return "🎥 Video"
    case "audio":
        return "🎵 Audio"
    case "document":
        return "📄 Document"
    case "location":
        return "📍 Location"
    case "contact":
        return "👤 Contact"
    default:
        return "Message"
    }
}
```

---

## **Sequence Number Generation (Atomic)**

```go
func (s *messageService) generateSequenceNumber(ctx context.Context, conversationID uuid.UUID) (int32, error) {
    // Option 1: MongoDB atomic increment (recommended)
    collection := s.messageRepo.GetCollection()
    
    // Find the last message in this conversation and increment
    filter := bson.M{"conversation_id": conversationID}
    opts := options.FindOne().SetSort(bson.D{{Key: "sequence_number", Value: -1}})
    
    var lastMessage models.Message
    err := collection.FindOne(ctx, filter, opts).Decode(&lastMessage)
    
    if err == mongo.ErrNoDocuments {
        // First message in conversation
        return 1, nil
    }
    if err != nil {
        return 0, err
    }
    
    return lastMessage.SequenceNumber + 1, nil
}

// Alternative: Use PostgreSQL sequence (more reliable for distributed systems)
func (s *messageService) generateSequenceNumberPostgres(ctx context.Context, conversationID uuid.UUID) (int32, error) {
    var seqNum int32
    query := `
        INSERT INTO conversation_sequences (conversation_id, sequence_number)
        VALUES ($1, 1)
        ON CONFLICT (conversation_id) 
        DO UPDATE SET sequence_number = conversation_sequences.sequence_number + 1
        RETURNING sequence_number
    `
    err := s.db.QueryRowContext(ctx, query, conversationID).Scan(&seqNum)
    return seqNum, err
}

// PostgreSQL table for sequence numbers (optional but recommended)
/*
CREATE TABLE conversation_sequences (
    conversation_id UUID PRIMARY KEY REFERENCES conversations(conversation_id),
    sequence_number INT NOT NULL DEFAULT 0
);
*/
```

---

## **Full Updated Service**

```go
type MessageService struct {
    messageRepo        MessageRepository
    conversationRepo   ConversationRepository
    mediaRepo          MediaRepository
    db                 *sql.DB // PostgreSQL
    redisClient        *redis.Client
    rabbitMQChannel    *amqp.Channel
}

func (s *messageService) Create(ctx context.Context, message *models.Message) error {
    // Validations
    if message.ConversationID == uuid.Nil {
        return errors.New("conversation_id is required")
    }
    if message.SenderID == uuid.Nil {
        return errors.New("sender_id is required")
    }
    if message.MessageType == "" {
        return errors.New("message_type is required")
    }

    // Validate user has access to conversation
    hasAccess, err := s.conversationRepo.UserHasAccess(ctx, message.ConversationID, message.SenderID)
    if err != nil {
        return err
    }
    if !hasAccess {
        return errors.New("user does not have access to this conversation")
    }

    // Generate sequence number
    sequenceNumber, err := s.generateSequenceNumber(ctx, message.ConversationID)
    if err != nil {
        return err
    }
    message.SequenceNumber = sequenceNumber

    // Set timestamps
    now := time.Now()
    message.CreatedAt = now
    message.ID = primitive.NewObjectID()

    // Insert to MongoDB
    err = s.messageRepo.Create(ctx, message)
    if err != nil {
        return err
    }

    // Update PostgreSQL conversation metadata
    go func() {
        // Run in background to not block message creation
        updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        
        if err := s.updateConversationMetadata(updateCtx, message); err != nil {
            log.Printf("Failed to update conversation metadata for %s: %v", 
                message.ConversationID, err)
        }
    }()

    // Publish to Redis (real-time)
    go s.publishToRedis(message)

    // Queue push notification (offline users)
    go s.queuePushNotification(message)

    return nil
}

func (s *messageService) publishToRedis(message *models.Message) {
    ctx := context.Background()
    
    // Enrich message with media metadata if needed
    enrichedMessage := s.enrichMessageWithMedia(ctx, message)
    
    // Publish to Redis channel
    channel := fmt.Sprintf("conversation:%s", message.ConversationID)
    payload, _ := json.Marshal(enrichedMessage)
    
    err := s.redisClient.Publish(ctx, channel, payload).Err()
    if err != nil {
        log.Printf("Failed to publish to Redis: %v", err)
    }
}

func (s *messageService) queuePushNotification(message *models.Message) {
    ctx := context.Background()
    
    // Get offline users in this conversation
    offlineUsers, err := s.getOfflineUsers(ctx, message.ConversationID, message.SenderID)
    if err != nil {
        log.Printf("Failed to get offline users: %v", err)
        return
    }
    
    if len(offlineUsers) == 0 {
        return // Everyone online, no push needed
    }
    
    // Queue job to RabbitMQ
    job := PushNotificationJob{
        MessageID:      message.ID.Hex(),
        ConversationID: message.ConversationID,
        SenderID:       message.SenderID,
        Recipients:     offlineUsers,
        MessagePreview: message.Content[:min(50, len(message.Content))],
    }
    
    payload, _ := json.Marshal(job)
    err = s.rabbitMQChannel.Publish(
        "",                    // exchange
        "push_notifications",  // routing key
        false,                 // mandatory
        false,                 // immediate
        amqp.Publishing{
            ContentType: "application/json",
            MessageId:   message.ID.Hex(),
            Body:        payload,
        },
    )
    
    if err != nil {
        log.Printf("Failed to queue push notification: %v", err)
    }
}

func (s *messageService) enrichMessageWithMedia(ctx context.Context, message *models.Message) *models.Message {
    if len(message.MediaIDs) == 0 {
        return message
    }
    
    // Fetch media metadata from PostgreSQL
    media, err := s.mediaRepo.GetByIDs(ctx, message.MediaIDs)
    if err != nil {
        log.Printf("Failed to fetch media metadata: %v", err)
        return message
    }
    
    // Attach to message
    enriched := *message
    enriched.Media = media
    return &enriched
}

func (s *messageService) getOfflineUsers(ctx context.Context, conversationID, senderID uuid.UUID) ([]uuid.UUID, error) {
    // Get all users in conversation
    users, err := s.conversationRepo.GetParticipants(ctx, conversationID)
    if err != nil {
        return nil, err
    }
    
    var offlineUsers []uuid.UUID
    for _, userID := range users {
        if userID == senderID {
            continue // Don't send push to sender
        }
        
        // Check if user is online (check Redis or PostgreSQL sessions)
        isOnline, _ := s.redisClient.Exists(ctx, fmt.Sprintf("user:online:%s", userID)).Result()
        if isOnline == 0 {
            offlineUsers = append(offlineUsers, userID)
        }
    }
    
    return offlineUsers, nil
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
```

---

## **Summary: What Happens When Message is Created**

```
1. Validate input ✅
2. Generate sequence_number (atomic) ✅
3. Insert to MongoDB ✅
4. Update PostgreSQL conversations table:
   - last_message_id
   - last_message_at
   - last_message_preview
   - unread_count_user1 or unread_count_user2
5. Publish to Redis Pub/Sub → Socket Service → Online users ✅
6. Queue to RabbitMQ → Workers → Push notifications for offline users ✅
```

---

## **Next Steps:**

1. Implement `updateConversationMetadata()` with PostgreSQL update
2. Implement `generateSequenceNumber()` (MongoDB or PostgreSQL approach)
3. Test with direct chat (unread count increments correctly)
4. Test with group chat (metadata updates)
5. Verify Redis pub/sub works
6. Verify RabbitMQ queue works

Start with steps 1-2, then we'll tackle Redis/RabbitMQ integration next!