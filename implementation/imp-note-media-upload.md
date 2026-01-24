**Great! Here's the efficient media upload flow:**

---

## **Recommended Flow: Frontend Direct Upload to S3**

```
1. Frontend requests upload URL from backend
2. Backend generates presigned S3 URL + creates media record
3. Frontend uploads directly to S3 (no backend bandwidth used)
4. Frontend gets media_id, includes in message
5. Backend creates message with media_ids
```

---

## **Implementation:**

### **Step 1: Upload Initiation Endpoint**

```go
// POST /api/media/upload/initiate
type InitiateUploadRequest struct {
    FileName string `json:"file_name" binding:"required"`
    FileSize int64  `json:"file_size" binding:"required"`
    MimeType string `json:"mime_type" binding:"required"`
    Checksum string `json:"checksum" binding:"required"` // SHA256 from frontend
}

type InitiateUploadResponse struct {
    MediaID      uuid.UUID `json:"media_id"`
    UploadURL    string    `json:"upload_url"`    // Presigned S3 URL
    ExpiresIn    int       `json:"expires_in"`    // Seconds (e.g., 300 = 5 min)
}

func (h *mediaHandler) InitiateUpload(c *gin.Context) {
    ctx := c.Request.Context()
    
    var req InitiateUploadRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    userID := getUserIDFromContext(c) // From JWT
    
    // 1. Check for duplicate (deduplication by checksum)
    existing, err := h.mediaService.GetByChecksum(ctx, req.Checksum, userID)
    if err == nil && existing != nil {
        // File already exists, return existing media
        c.JSON(http.StatusOK, gin.H{
            "media_id": existing.MediaID,
            "cdn_url":  existing.CDNURL,
            "exists":   true,
        })
        return
    }
    
    // 2. Validate file
    if err := h.mediaService.ValidateUpload(req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    // 3. Create media record and get presigned URL
    response, err := h.mediaService.InitiateUpload(ctx, userID, req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    
    c.JSON(http.StatusOK, response)
}
```

---

### **Step 2: Media Service - Generate Presigned URL**

```go
func (s *mediaService) InitiateUpload(ctx context.Context, userID uuid.UUID, req InitiateUploadRequest) (*InitiateUploadResponse, error) {
    // 1. Generate unique file path
    mediaID := uuid.New()
    ext := filepath.Ext(req.FileName)
    fileKey := fmt.Sprintf("uploads/%s/%s/%s%s", 
        time.Now().Format("2006/01"),  // uploads/2026/01/
        userID.String(),                 // user-id/
        mediaID.String(),                // unique-id
        ext,                             // .jpg
    )
    
    // 2. Generate presigned S3 URL (5 minute expiry)
    presignedURL, err := s.s3Client.GeneratePresignedPutURL(fileKey, req.MimeType, 5*time.Minute)
    if err != nil {
        return nil, err
    }
    
    // 3. Determine media type from MIME
    mediaType := s.getMediaTypeFromMime(req.MimeType)
    
    // 4. Create media record in PostgreSQL (status: pending)
    cdnURL := fmt.Sprintf("https://cdn.yourdomain.com/%s", fileKey)
    
    media := &models.MediaFile{
        MediaID:    mediaID,
        UploadedBy: userID,
        FileName:   req.FileName,
        FilePath:   fileKey,
        CDNURL:     cdnURL,
        MediaType:  mediaType,
        FileSize:   req.FileSize,
        MimeType:   req.MimeType,
        Checksum:   req.Checksum,
        UploadedAt: time.Now(),
        Metadata:   json.RawMessage(`{"status": "pending"}`),
    }
    
    err = s.mediaRepo.Create(ctx, media)
    if err != nil {
        return nil, err
    }
    
    return &InitiateUploadResponse{
        MediaID:   mediaID,
        UploadURL: presignedURL,
        ExpiresIn: 300, // 5 minutes
    }, nil
}

func (s *mediaService) getMediaTypeFromMime(mimeType string) string {
    switch {
    case strings.HasPrefix(mimeType, "image/"):
        return "image"
    case strings.HasPrefix(mimeType, "video/"):
        return "video"
    case strings.HasPrefix(mimeType, "audio/"):
        return "audio"
    default:
        return "document"
    }
}

func (s *mediaService) ValidateUpload(req InitiateUploadRequest) error {
    // Max file size: 100MB
    if req.FileSize > 100*1024*1024 {
        return errors.New("file too large (max 100MB)")
    }
    
    // Allowed MIME types
    allowedMimes := []string{
        "image/jpeg", "image/png", "image/gif", "image/webp",
        "video/mp4", "video/quicktime",
        "audio/mpeg", "audio/mp4",
        "application/pdf",
    }
    
    allowed := false
    for _, mime := range allowedMimes {
        if req.MimeType == mime {
            allowed = true
            break
        }
    }
    
    if !allowed {
        return errors.New("file type not allowed")
    }
    
    return nil
}
```

---

### **Step 3: S3 Client (Aliyun OSS)**

```go
type S3Client struct {
    client *oss.Client
    bucket string
}

func (s *S3Client) GeneratePresignedPutURL(key, contentType string, expiry time.Duration) (string, error) {
    bucket, err := s.client.Bucket(s.bucket)
    if err != nil {
        return "", err
    }
    
    options := []oss.Option{
        oss.ContentType(contentType),
    }
    
    signedURL, err := bucket.SignURL(key, oss.HTTPPut, int64(expiry.Seconds()), options...)
    if err != nil {
        return "", err
    }
    
    return signedURL, nil
}
```

---

### **Step 4: Frontend Upload Flow**

```javascript
// Frontend (React Native / Web)

// 1. Calculate checksum
const file = await pickImage();
const checksum = await calculateSHA256(file);

// 2. Request upload URL
const response = await fetch('/api/media/upload/initiate', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    file_name: file.name,
    file_size: file.size,
    mime_type: file.type,
    checksum: checksum
  })
});

const { media_id, upload_url, exists } = await response.json();

if (exists) {
  // File already uploaded (deduplication)
  sendMessage({ media_ids: [media_id] });
  return;
}

// 3. Upload directly to S3
await fetch(upload_url, {
  method: 'PUT',
  headers: { 'Content-Type': file.type },
  body: file
});

// 4. Send message with media_id
sendMessage({ 
  content: "Check this out!",
  media_ids: [media_id] 
});
```

---

### **Step 5: Message Creation (Your Existing Code)**

```go
// Frontend sends:
POST /api/messages/send
{
  "conversation_id": "...",
  "content": "Check this out!",
  "media_ids": ["media-uuid-1", "media-uuid-2"],
  "message_type": "image"
}

// Your existing Create function works as-is!
// Media already exists in PostgreSQL
// Just reference by media_ids
```

---

## **Optional: Confirmation Endpoint**

```go
// POST /api/media/{media_id}/confirm
// Call this after successful S3 upload to mark as "completed"

func (s *mediaService) ConfirmUpload(ctx context.Context, mediaID uuid.UUID) error {
    return s.mediaRepo.UpdateStatus(ctx, mediaID, "completed")
}

// Update metadata
UPDATE media_files 
SET metadata = jsonb_set(metadata, '{status}', '"completed"')
WHERE media_id = $1
```

---

## **Deduplication (Bonus)**

```go
func (r *mediaRepository) GetByChecksum(ctx context.Context, checksum string, userID uuid.UUID) (*models.MediaFile, error) {
    var media models.MediaFile
    
    err := r.db.WithContext(ctx).
        Where("checksum = ? AND uploaded_by = ?", checksum, userID).
        First(&media).Error
    
    if err == gorm.ErrRecordNotFound {
        return nil, nil
    }
    
    return &media, err
}
```

**If user uploads same file twice → Return existing media_id (saves storage!)**

---

## **Summary Flow:**

```
Frontend                  Backend                    S3/OSS
   |                         |                         |
   |--1. Initiate Upload---->|                         |
   |     (file metadata)     |                         |
   |                         |--Create media record--->|
   |                         |    (PostgreSQL)         |
   |<--2. Upload URL---------|                         |
   |    (presigned URL)      |                         |
   |                         |                         |
   |--3. Upload file---------------------------------->|
   |    (direct to S3)       |                         |
   |                         |                         |
   |--4. Send message------->|                         |
   |    (with media_ids)     |                         |
   |                         |--Create message-------->|
   |                         |   (MongoDB)             |
```

---

**Benefits:**
- ✅ No backend bandwidth used for uploads
- ✅ Deduplication (checksum matching)
- ✅ Scalable (S3 handles the load)
- ✅ Fast (direct upload, no proxy)

**Start with the initiate endpoint, then your existing message creation works as-is!**