

## **For Media Enrichment:**

**In the service layer.**:

```go
func (s *messageService) GetByConversationIDWithCursor(ctx context.Context, conversationID uuid.UUID, lastTimestamp *time.Time, lastMessageID *primitive.ObjectID, limit int64, direction string) ([]models.Message, error) {
	// ... your existing validation code ...

	// 1. Fetch messages from MongoDB
	messages, err := s.messageRepo.GetByConversationIDWithCursor(ctx, conversationID, lastTimestamp, lastMessageID, limit, direction)
	if err != nil {
		return nil, err
	}

	// 2. Enrich with media metadata
	enrichedMessages, err := s.enrichMessagesWithMedia(ctx, messages)
	if err != nil {
		// Log error but return messages without media enrichment
		// Don't fail the whole request if media fetch fails
		log.Printf("Failed to enrich messages with media: %v", err)
		return messages, nil
	}

	return enrichedMessages, nil
}

func (s *messageService) enrichMessagesWithMedia(ctx context.Context, messages []models.Message) ([]models.Message, error) {
	// 1. Collect all media IDs from all messages
	mediaIDSet := make(map[uuid.UUID]struct{})
	for _, msg := range messages {
		for _, mediaID := range msg.MediaIDs {
			mediaIDSet[mediaID] = struct{}{}
		}
	}

	if len(mediaIDSet) == 0 {
		return messages, nil // No media to enrich
	}

	// 2. Convert set to slice
	var mediaIDs []uuid.UUID
	for id := range mediaIDSet {
		mediaIDs = append(mediaIDs, id)
	}

	// 3. Batch fetch media from PostgreSQL (ONE query for all)
	mediaList, err := s.mediaRepo.GetByIDs(ctx, mediaIDs)
	if err != nil {
		return nil, err
	}

	// 4. Create map for fast lookup
	mediaMap := make(map[uuid.UUID]models.MediaFile)
	for _, media := range mediaList {
		mediaMap[media.MediaID] = media
	}

	// 5. Attach media to each message
	for i := range messages {
		if len(messages[i].MediaIDs) > 0 {
			messages[i].Media = []models.MediaFile{}
			for _, mediaID := range messages[i].MediaIDs {
				if media, found := mediaMap[mediaID]; found {
					messages[i].Media = append(messages[i].Media, media)
				}
			}
		}
	}

	return messages, nil
}
```

---

## **Media Repository Method:**

```go
// In your media repository
func (r *mediaRepository) GetByIDs(ctx context.Context, mediaIDs []uuid.UUID) ([]models.MediaFile, error) {
	var mediaFiles []models.MediaFile
	
	query := `
		SELECT media_id, file_name, cdn_url, mime_type, file_size, metadata
		FROM media_files
		WHERE media_id = ANY($1)
	`
	
	err := r.db.WithContext(ctx).Raw(query, pq.Array(mediaIDs)).Scan(&mediaFiles).Error
	if err != nil {
		return nil, err
	}
	
	return mediaFiles, nil
}
```

---

## **Why Service Layer (Not Repository):**

✅ **Repository** = Pure data access (MongoDB, PostgreSQL separately)  
✅ **Service** = Business logic (combine data from multiple sources)

**Repository shouldn't know about other repositories.**

---

## **Performance:**

- Fetches 50 messages from MongoDB
- Extracts all unique media IDs (e.g., 20 media files)
- **ONE PostgreSQL query** to fetch all 20 media files
- Maps media back to messages

**Efficient!** No N+1 queries.

---

**You're on the right track!** 🚀