## **Major Architectural Upgrades**

This version adds:
- **CDN & WAF** for global delivery and security
- **Database replication** (Master-Replica) for high availability
- **Redis Cluster** for distributed caching
- **Elasticsearch** for advanced search
- **Service decomposition** (Chat Service split into multiple specialized services)

---

## **Complete Flow: Start to End**

### **1. Entry Point & Security Layer (Steps 1-3)**

**Process:**
1. Client sends request (HTTP/WebSocket)
2. **CloudFront CDN** receives request
   - Caches static assets (images, JS, CSS)
   - Routes to nearest edge location globally
   - Reduces latency for users worldwide
3. **WAF (Web Application Firewall)** inspects traffic
   - DDoS protection (blocks flood attacks)
   - SQL injection prevention
   - Rate limiting per IP/user
   - Bot detection
4. **Nginx Load Balancer** distributes clean traffic

**Why this matters:**
- CDN: User in Tokyo gets content from Asian edge, not US datacenter
- WAF: Blocks 99% of malicious traffic before it hits your servers
- Multi-layer defense: Attack must bypass CDN → WAF → LB

---

### **2. Gateway Layer (Steps 4-5)**

**Process:**
4. Load Balancer routes to appropriate gateway:
   - **REST API Gateway (Gin)** ← HTTP requests
   - **WebSocket Gateway (Gorilla WS)** ← WebSocket connections

**Improvements over basic design:**
- Gateways now enforce rate limiting per user
- Built-in request tracing for debugging
- API versioning support (v1, v2 endpoints)

---

### **3. Authentication & Authorization (Steps 6-8)**

**Process:**
6. API Gateway forwards to **Auth Service**
7. Auth Service validates credentials with **PostgreSQL Master**
   - Checks username/password hash
   - **NEW: 2FA verification** (TOTP codes, SMS)
8. Session token stored in **Redis Cluster**
   - Distributed cache (not single Redis instance)
   - Sub-millisecond token lookup
   - Automatic expiration

**Master-Replica Pattern:**
- **PostgreSQL Master**: Handles all writes (user registration, password changes)
- **PostgreSQL Replica**: Read-only copies for queries
- Reduces load on master, improves read performance

---

### **4. User Profile Operations (Steps 9-11)**

**Process:**
9. API Gateway routes to **User Service** (new dedicated service)
10. User Service reads from **PostgreSQL Replica**
    - Profile data, settings, preferences
    - Uses replica to offload master database
11. Frequently accessed data cached in **Redis**
    - User avatar URLs, display names
    - Reduces database hits by 80%+

**Why separate User Service:**
- Independent scaling (profiles accessed more than auth)
- Clear separation of concerns
- Can update profiles without touching auth logic

---

### **5. Real-Time Chat Flow (Steps 12-19) - CORE FEATURE**

**Process:**

**A. Message Reception (Steps 12-14)**
12. WebSocket Gateway receives message from client
13. Routes to **Chat Service**
14. Chat Service forwards to **Message Service** (new specialized service)
15. Message Service writes to **MongoDB Master**
    - Primary copy of message
    - Replicated to MongoDB replicas automatically

**B. Instant Delivery (Steps 15-17)**
15. Chat Service publishes to **Redis Cluster Pub/Sub**
    - Message sent to channel: `chat:room:123`
16. Redis broadcasts to **ALL WebSocket Gateway instances**
    - Handles 10,000+ concurrent connections per gateway
17. WebSocket Gateways push to connected clients **instantly**

**C. Presence Updates (Step 18)**
18. WebSocket Gateway updates **user presence** in Redis
    - "Alice is online"
    - "Bob is typing in Room #general"
    - Last seen timestamp

**Key Improvement:**
- **Redis Cluster** (not single Redis):
  - Distributed across multiple nodes
  - Handles millions of pub/sub messages/second
  - Automatic failover if node dies

---

### **6. REST Chat Operations (Steps 19-20)**

**Process:**
19. API Gateway receives request (e.g., "get chat history")
20. Chat Service checks Redis for:
    - Online users in this chat
    - Unread message count
    - Cached recent messages

**Caching Strategy:**
- Last 50 messages per chat cached in Redis
- Avoids hitting MongoDB for every page load
- Cache invalidated when new message arrives

---

### **7. Analytics Pipeline (Steps 21-23) - NEW FEATURE**

**Process:**
21. Message Service queues analytics event to **RabbitMQ**
    - Message sent timestamp
    - User activity
    - Response time metrics
22. **Analytics Service** consumes job
23. Stores in **PostgreSQL Master**
    - Daily active users (DAU)
    - Message volume per hour
    - Peak usage times

**Business Value:**
- Track user engagement
- Identify popular features
- Capacity planning

---

### **8. Background Jobs Queue (Steps 24-28)**

**Process:**

After every message sent, **4 separate jobs** queued to RabbitMQ:

**Job 1: Push Notifications (Steps 24, 28)**
- Notification Service consumes
- Sends to offline users via FCM (Android) / APNS (iOS)
- Example: "Alice: Hello!" notification on Bob's locked phone

**Job 2: Email Notifications (Step 25)**
- For users with email alerts enabled
- "@mention" notifications sent to email
- Digest emails (e.g., "You have 15 unread messages")

**Job 3: Offline Delivery (Step 26)**
- Mobile apps sync messages when reconnecting
- Ensures no messages lost during airplane mode

**Job 4: Mention Detection (Step 27)**
- Scans message for "@username"
- Creates mention record in database
- Triggers special notification

**Why RabbitMQ:**
- Jobs persist if worker crashes
- Priority queues (push notifications processed before analytics)
- Dead letter queue for failed jobs

---

### **9. Message History & Search (Steps 29-30)**

**Process:**

**A. Reading History (Step 29)**
- Message Service reads from **MongoDB Replica**
- Pagination: 50 messages at a time
- Replica ensures master isn't overwhelmed by read queries

**B. Search Indexing (Step 30) - NEW FEATURE**
- Messages indexed in **Elasticsearch asynchronously**
- Full-text search: "find messages containing 'project deadline'"
- Advanced queries: date ranges, sender filters, attachments only

**Elasticsearch Benefits:**
- Search across millions of messages in <100ms
- Fuzzy matching ("projct" finds "project")
- Relevance scoring

---

### **10. Group/Channel Management (Steps 31-33)**

**Process:**
31. API Gateway routes to **Group Service** (new dedicated service)
32. Group Service writes to **PostgreSQL Master**:
    - Create channel
    - Add/remove members
    - Update permissions (admin, moderator)
33. Sync group member cache to **Redis**
    - Who can access this channel
    - Permission checks done in-memory

**Why separate Group Service:**
- Complex permission logic isolated
- Group operations don't slow down messaging
- Easier to add features (polls, threads)

---

### **11. Media Upload & Processing (Steps 34-40)**

**Process:**

**A. Upload (Steps 34-35)**
34. API Gateway routes to **Media Service**
35. Media Service uploads file to **AWS S3 / Aliyun OSS**
    - Original image (5MB JPEG)
    - Stored with unique ID: `media/2026/01/abc123.jpg`

**B. Background Processing (Steps 36-37)**
36. Media Service queues **2 jobs** to RabbitMQ:
    - **Transcoding job**: Convert video formats (MP4 → WebM)
    - **Thumbnail job**: Generate preview image

**C. Processing (Steps 38-40)**
38. Media Service workers consume jobs
39. Store processed media to **S3**:
    - `media/2026/01/abc123_thumb.jpg` (thumbnail)
    - `media/2026/01/abc123_720p.mp4` (compressed video)
40. Update metadata in **PostgreSQL Master**:
    - Original size: 5MB
    - Thumbnail size: 50KB
    - Processing status: "completed"

**Why async processing:**
- User doesn't wait for video transcoding (can take minutes)
- Distributes heavy CPU work across worker pool
- Failed jobs automatically retried

---

### **12. Search Operations (Steps 41-43) - NEW FEATURE**

**Process:**
41. API Gateway routes to **Search Service**
42. Search Service queries **Elasticsearch**:
    - "Find messages from Alice mentioning 'budget'"
    - Returns results ranked by relevance
43. Frequent searches cached in **Redis**:
    - "recent messages" → cached for 30 seconds
    - Reduces Elasticsearch load

**Search Capabilities:**
- Full-text: "find messages containing X"
- User search: "find users named John"
- File search: "find PDFs shared last week"

---

### **13. Audio Call Flow (Steps 44-59) - GetStream.io**

**Initiation (Steps 44-49):**
44. Client taps "Call" button
45. API Gateway → Chat Service
46. Chat Service calls **GetStream.io API**:
    - "Create audio call session for Alice → Bob"
47. GetStream returns:
    - Session ID: `call_abc123`
    - Auth token: `eyJhbGc...`
    - TURN/STUN servers: `turn:relay.getstream.io`
48. Chat Service stores in **Redis**: `call:abc123 → {status: ringing, participants: [Alice, Bob]}`
49. Chat Service logs to **PostgreSQL Master**:
    - Call ID, start time, participants
50. Credentials sent to client

**Connection (Steps 50-51):**
50. Client connects to **GetStream SDK**
    - Tries P2P (direct connection) first
    - Falls back to TURN relay if behind NAT
51. Audio streams via WebRTC:
    - Opus codec (low latency)
    - Adaptive bitrate (adjusts to network)

**Signaling (Steps 52-55):**
52. WebSocket Gateway receives events:
    - "Bob's phone is ringing"
    - "Bob answered"
    - "Alice put call on hold"
53. Chat Service publishes to **Redis**: `PUBLISH call:abc123 {"event": "answered"}`
54. Redis broadcasts to all WebSocket instances
55. All participants receive real-time updates

**Termination (Steps 56-59):**
56. Client sends "End call"
57. GetStream webhook:
    ```json
    {
      "call_id": "abc123",
      "duration": 180,
      "quality_score": 4.2,
      "packet_loss": "0.5%"
    }
    ```
58. Chat Service updates **PostgreSQL**: End time, duration, quality
59. Queues analytics job: Call statistics for reporting

---

### **14. Video Call Flow (Steps 60-75) - Aliyun Apsara**

**Initiation (Steps 60-65):**
60. Client taps "Video Call"
61. API Gateway → Chat Service
62. Chat Service calls **Aliyun Apsara API**:
    - "Create video room for 4 participants"
63. Aliyun returns:
    - Room ID: `room_xyz789`
    - Access token
    - **SFU endpoint**: `sfu-asia.aliyuncs.com`
64. Chat Service caches in **Redis**: `video:xyz789 → {status: active, participants: 4}`
65. Logs to **PostgreSQL Master**
66. Credentials sent to client

**Connection (Steps 66-67):**
66. Client joins room via **Aliyun SDK**
67. Video/audio streaming via **SFU (Selective Forwarding Unit)**:
    - Client uploads 1 stream → SFU
    - SFU sends N streams to each participant
    - More efficient than P2P for multi-party calls

**Signaling (Steps 68-71):**
68. WebSocket Gateway forwards events:
    - "Charlie enabled camera"
    - "Dana started screen share"
    - "Eva muted microphone"
69. Chat Service publishes to **Redis**
70. Redis broadcasts to all WebSocket instances
71. All participants see updates in real-time

**Termination (Steps 72-75):**
72. Client leaves room
73. Aliyun webhook:
    ```json
    {
      "room_id": "xyz789",
      "duration": 1200,
      "max_participants": 4,
      "total_data": "2.5GB",
      "quality_avg": 4.7
    }
    ```
74. Chat Service updates **PostgreSQL**: Final statistics
75. Queues analytics job: Video usage metrics

---

## **Key Architectural Improvements**

### **1. High Availability (HA)**

**Master-Replica Pattern:**
- **PostgreSQL**: 1 Master (writes) + 2+ Replicas (reads)
  - If master fails → promote replica to master
  - Zero data loss with synchronous replication
- **MongoDB**: Same pattern for chat messages
  - Replica set with automatic failover

**Redis Cluster:**
- 6+ nodes (3 masters, 3 replicas)
- Data sharded across masters
- If node fails → replica takes over instantly

**Load Balancer:**
- Multiple Nginx instances
- Health checks every 5 seconds
- Removes unhealthy backends automatically

---

### **2. Scalability**

**Horizontal Scaling:**
- **WebSocket Gateways**: Add more instances as users grow
  - Redis Pub/Sub ensures messages reach all instances
- **Message Service**: Add workers to handle message volume
- **Media Service**: Add workers for video processing

**Database Scaling:**
- **Read replicas**: Add more replicas for read-heavy workloads
- **Sharding**: Split MongoDB across multiple clusters (e.g., by date)
- **Elasticsearch**: Add nodes to index more messages

---

### **3. Performance Optimization**

**Caching Strategy:**
| Data Type | Storage | TTL |
|-----------|---------|-----|
| User profiles | Redis | 1 hour |
| Recent messages | Redis | 5 minutes |
| Session tokens | Redis | 24 hours |
| Search results | Redis | 30 seconds |
| Group members | Redis | 10 minutes |

**Database Optimization:**
- **Write to master**: Authentication, new messages, group changes
- **Read from replica**: History, profiles, search
- Reduces master load by 70-80%

**CDN Caching:**
- Static assets: 30 days
- User avatars: 7 days
- Media thumbnails: 1 day
- Reduces bandwidth costs by 60%+

---

### **4. Service Decomposition**

**Microservices Breakdown:**

| Service | Responsibility |
|---------|---------------|
| **Auth Service** | Login, JWT, 2FA |
| **User Service** | Profiles, settings, preferences |
| **Chat Service** | Orchestration, call setup |
| **Group Service** | Channels, permissions |
| **Message Service** | Message persistence, delivery |
| **Media Service** | Upload, processing, storage |
| **Notification Service** | Push, email, SMS |
| **Search Service** | Full-text search, filters |
| **Analytics Service** | Metrics, reporting, insights |

**Benefits:**
- Independent deployment (update Search without touching Chat)
- Independent scaling (scale Message Service during peak hours)
- Team ownership (Search team owns Search Service)
- Fault isolation (Analytics crash doesn't affect messaging)

---

### **5. Observability**

**Monitoring Points:**
- **CDN**: Cache hit rate, bandwidth
- **WAF**: Blocked requests, DDoS attempts
- **Load Balancer**: Request distribution, health checks
- **Databases**: Query performance, replication lag
- **Redis**: Memory usage, pub/sub throughput
- **RabbitMQ**: Queue depth, job processing time
- **Services**: Response time, error rate

**Tracing:**
- Request ID follows entire journey:
  - Client → CDN → WAF → LB → Gateway → Service → Database
- Debug issues: "Why did message take 5 seconds?"

---

## **Complete User Journey: Alice Video Calls Bob**

1. **Alice opens app** (Tokyo):
   - CDN serves app from Tokyo edge location (50ms latency)
   - WebSocket connects to nearest gateway
   - Redis shows "Alice online"

2. **Alice searches "Bob"**:
   - Search Service queries Elasticsearch
   - Result cached in Redis
   - Returns in 80ms

3. **Alice starts video call**:
   - API Gateway → Chat Service
   - Chat Service → Aliyun Apsara creates room
   - Redis caches call state
   - PostgreSQL logs call start
   - Alice receives SFU credentials

4. **Bob's phone receives call**:
   - Chat Service → Redis Pub/Sub
   - Redis → All WebSocket Gateways
   - Bob's gateway sends push notification
   - Bob's phone rings

5. **Bob answers**:
   - Bob connects to Aliyun SFU (Hong Kong region)
   - Video/audio streams via SFU
   - WebSocket signals "Bob joined"
   - Redis broadcasts update
   - Alice sees Bob's video

6. **They talk for 10 minutes**:
   - SFU handles adaptive bitrate
   - Network congestion → lower resolution
   - WebSocket keeps signaling active

7. **Call ends**:
   - Aliyun webhook → Chat Service
   - PostgreSQL updated: 10 min duration
   - RabbitMQ job: Analytics (10 min video usage)
   - Analytics Service updates daily metrics

8. **Alice sends message "Thanks for the call!"**:
   - WebSocket → Message Service
   - MongoDB stores message
   - Redis Pub/Sub → Bob receives instantly
   - Bob offline? → Push notification queued

---

## **System Capacity**

This architecture can handle:
- **10 million+ concurrent users**
- **100,000+ messages/second**
- **50,000+ simultaneous video calls**
- **Petabyte-scale message history**
- **<100ms message delivery latency globally**
- **99.99% uptime** (52 minutes downtime/year)