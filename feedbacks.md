Ah perfect! Then let me focus **purely on the system/infrastructure side** - the flows, components, and how they communicate.

## **System-Level Critical Fixes** 🔧

### **1. Redis Pub/Sub → Redis Streams (Architecture Change)**

**Current Flow (Both Diagrams):**
```
CHAT->>REDIS: PUBLISH to channel (fanout to all connected clients)
REDIS-->>WSGATE: Message propagated to all WS instances
```

**Problem:** Pub/Sub is fire-and-forget
- Message published while client disconnected = **lost forever**
- No message history/replay
- No ordering guarantees across consumers

**Better Architecture:**
```
CHAT->>REDIS STREAMS: XADD to stream (persistent log)
WSGATE->>REDIS STREAMS: XREAD with consumer groups
REDIS STREAMS-->>WSGATE: Deliver messages in order
WSGATE-->>Clients: Real-time delivery
```

**Why Streams:**
- Messages persist (can replay on reconnect)
- Consumer groups (multiple WS gateways coordinate)
- Guaranteed ordering per stream
- Built-in "last read" tracking

**System Impact:**
- ✅ No new infrastructure (already using Redis)
- ✅ Backward compatible (can run both during migration)
- ✅ Solves reconnection problem automatically

---

### **2. WebSocket Gateway Needs State Management**

**Current Diagrams Show:**
```
WSGATE-->>CLIENT: Real-time message delivery via WebSocket
```

**Missing:** How does WS Gateway know which users are connected to which instance?

**Add Connection Registry in Redis:**

```
┌─────────────────────────────────────────────┐
│         WebSocket Gateway #1                │
│  • Connected Users: Alice, Bob, Charlie     │
│  • Redis Key: ws:instance:1:users           │
└─────────────────────────────────────────────┘
                    ▼
            [Redis Cluster]
         ┌────────────────────┐
         │ ws:instance:1:users│ → [Alice, Bob, Charlie]
         │ ws:instance:2:users│ → [Dave, Eve]
         │ user:Alice:instance│ → 1
         │ user:Bob:instance  │ → 1
         └────────────────────┘
```

**Why This Matters:**
- When message arrives: "Which WS instance has Alice?"
- When instance crashes: "Move Alice's connection to instance 2"
- Load balancing: "Instance 1 has 10k users, route new connections to instance 2"

**Add to Diagram Flow:**
```
WSGATE->>REDIS: Register connected user
REDIS-->>WSGATE: Confirm registration
[User disconnects]
WSGATE->>REDIS: Deregister user
```

---

### **3. Background Job Failure Handling**

**Current Flow:**
```
CHAT->>RABBIT: Queue: Push Notification Job
RABBIT->>NOTIF: Consume push notification job
```

**What if Notification Worker crashes mid-job?**

**Add Dead Letter Queue (DLQ):**

```
┌──────────────┐
│  RabbitMQ    │
├──────────────┤
│ Main Queue   │ ──(job fails 3x)──> │ Dead Letter Queue │
│              │                       │  (manual review)  │
└──────────────┘                       └───────────────────┘
         │
         ▼
   ┌──────────┐
   │  Worker  │ ─(retry)─> Main Queue
   └──────────┘
```

**Configuration:**
```
Queue: push_notifications
  - maxRetries: 3
  - retryDelay: 30s exponential backoff
  - DLQ: push_notifications_failed

Queue: email_notifications
  - maxRetries: 5
  - retryDelay: 60s
  - DLQ: email_notifications_failed
```

**Add Monitoring Flow:**
```
RABBIT->>ANALYTICS: Job failure metrics
ANALYTICS->>PGMASTER: Log failed job details
[If DLQ depth > 100]
ANALYTICS->>NOTIFY: Alert on-call engineer
```

---

### **4. Database Replication Lag Monitoring**

**v2 Diagram Shows:**
```
USER->>PGREPLICA: Read user profile data
MSG->>MONGOREPLICA: Read message history
```

**Problem:** What if replica is 30 seconds behind master?

**User Experience:**
```
1. Alice sends message (written to MongoDB Master)
2. Bob immediately queries history (reads from Replica)
3. Bob doesn't see Alice's message yet (replica lag)
4. Bob thinks message failed
```

**Add Lag Detection:**

```
┌──────────────────┐
│  PostgreSQL      │
│                  │
│  Master ──────> Replica
│    │              │
│    │ (lag > 5s?) │
│    └────────────> Alert
└──────────────────┘
```

**System Flow:**
```
MSG->>MONGOREPLICA: Query message history
MONGOREPLICA->>MSG: Return data + replication_lag_ms
[If lag > 5000ms]
MSG->>MONGOMASTER: Fallback to master (slow but consistent)
MSG-->>Client: Return data + warning: "may be delayed"
```

**Add Health Check:**
```
Note over MONGOMASTER,MONGOREPLICA: Health check every 10s<br/>If lag > 30s, route reads to Master
```

---

### **5. Load Balancer Health Checks**

**Current:**
```
LB->>APIGW: Route HTTP/REST traffic
LB->>WSGW: Route WebSocket traffic
```

**Missing:** How does LB know if gateway is healthy?

**Add Health Check Endpoints:**

```
┌──────────────┐
│ Load Balancer│
└──────────────┘
       │
       ├─(every 5s)──> GET /health ──> API Gateway
       │                              ├─ Check: Can connect to Redis?
       │                              ├─ Check: Can connect to Postgres?
       │                              ├─ Check: Response time < 100ms?
       │                              └─ Return: 200 OK or 503 Unhealthy
       │
       └─(every 5s)──> GET /health ──> WebSocket Gateway
                                      ├─ Check: Redis Streams reachable?
                                      ├─ Check: Active connections < 50k?
                                      └─ Return: 200 OK or 503 Unhealthy
```

**Add to Diagram:**
```
LB->>APIGW: Health check (every 5s)
APIGW->>REDIS: Ping
APIGW->>PGMASTER: SELECT 1
APIGW-->>LB: 200 OK (healthy)

[If health check fails]
LB->>APIGW: Mark unhealthy, stop routing traffic
LB->>ANALYTICS: Alert: Gateway down
```

---

### **6. Service-to-Service Communication Timeout**

**Current Flow:**
```
APIGW->>CHAT: Chat history/status requests
CHAT->>REDIS: Check user/chat presence cache
```

**What if Chat Service is slow/hung?**

**Add Timeout & Circuit Breaker:**

```
┌────────────┐
│ API Gateway│
└────────────┘
      │
      ├─(timeout: 3s)──> Chat Service
      │                    │
      │                    ├─(hung, no response)
      │                    │
      └─(3s elapsed)──> Return 503 to client
                        Circuit Breaker: OPEN
                        (stop sending requests for 30s)
```

**System Pattern:**
```
APIGW->>CHAT: Request (timeout: 3s)
[After 3s, no response]
APIGW-->>Client: 503 Service Temporarily Unavailable
APIGW->>ANALYTICS: Log timeout incident
APIGW: Circuit breaker OPEN for 30s
[Next 30s]
APIGW-->>Client: 503 (fast fail, don't call Chat Service)
[After 30s]
APIGW->>CHAT: Test request (circuit breaker HALF-OPEN)
[If success]
APIGW: Circuit breaker CLOSED (resume normal operation)
```

---

### **7. Media Processing Async Flow Improvement**

**Current v2:**
```
MEDIA->>RABBIT: Queue: Transcoding job
MEDIA->>RABBIT: Queue: Thumbnail generation job
RABBIT->>MEDIA: Consume media processing jobs
```

**Problem:** User uploads video, when is it ready?

**Add Status Tracking:**

```
┌──────────────────────────────────────────────┐
│  Client uploads video                        │
│  ↓                                            │
│  MEDIA->>S3: Store original (video.mp4)      │
│  MEDIA->>PGMASTER: Create media record       │
│    • status: "processing"                    │
│    • job_id: "job_123"                       │
│  MEDIA->>RABBIT: Queue transcoding job       │
│  MEDIA-->>Client: 202 Accepted + job_id      │
│                                               │
│  [Background]                                 │
│  RABBIT->>MEDIA: Worker processes job        │
│  MEDIA->>S3: Upload processed video          │
│  MEDIA->>PGMASTER: Update status="completed" │
│  MEDIA->>REDIS: PUBLISH media:ready event    │
│  REDIS-->>WSGATE: Notify client via WebSocket│
│  WSGATE-->>Client: "Your video is ready!"   │
└──────────────────────────────────────────────┘
```

**Add to Diagram:**
```
MEDIA->>PGMASTER: Update media status: "processing"
RABBIT->>MEDIA: Consume media processing job
MEDIA->>S3: Store processed media
MEDIA->>PGMASTER: Update media status: "completed"
MEDIA->>REDIS: PUBLISH media:ready:{media_id}
REDIS-->>WSGATE: Media ready event
WSGATE-->>Clients: Notify user via WebSocket
```

---

### **8. CDN Cache Invalidation (v2 Diagram)**

**Current:**
```
Clients->>CDN: HTTP / WebSocket Request
CDN->>WAF: Forward request with caching
```

**Problem:** User updates profile picture, CDN still serves old image for 24 hours

**Add Cache Purge Flow:**

```
USER->>MEDIA: Upload new avatar
MEDIA->>S3: Store new avatar (avatar_v2.jpg)
MEDIA->>CDN: Purge cache for /avatars/user_123/*
MEDIA->>PGMASTER: Update avatar URL
CDN->>CDN: Delete cached version
MEDIA-->>USER: Avatar updated
[Next request]
Clients->>CDN: Request avatar
CDN->>S3: Cache miss, fetch new avatar
CDN->>CDN: Cache for 24h
CDN-->>Clients: Return new avatar
```

**Alternative: Cache Busting (simpler):**
```
Old URL: /avatars/user_123/avatar.jpg
New URL: /avatars/user_123/avatar.jpg?v=1705234567
         (timestamp forces CDN to fetch new)
```

---

### **9. Redis Cluster Failover (v2 Diagram)**

**Current:**
```
REDIS: Redis Cluster (Real-time Pub/Sub)
```

**What happens when Redis master node fails?**

**Add Sentinel/Cluster Management:**

```
┌─────────────────────────────────────┐
│       Redis Cluster                 │
│                                     │
│  Master-1  Master-2  Master-3      │
│     │         │         │          │
│  Replica-1 Replica-2 Replica-3     │
│                                     │
│  [Master-1 crashes]                │
│     ↓                               │
│  Sentinel detects failure          │
│     ↓                               │
│  Promotes Replica-1 to Master      │
│     ↓                               │
│  Update clients: new master IP     │
└─────────────────────────────────────┘
```

**Add Monitoring Flow:**
```
Note over REDIS: Redis Sentinel monitors health<br/>Automatic failover < 30s<br/>Client libraries auto-reconnect
```

---

### **10. GetStream/Aliyun Webhook Reliability**

**Current:**
```
GETSTREAM->>CHAT: Webhook with statistics
CHAT->>PGMASTER: Update call record
```

**Problem:** Webhook fails (network issue, Chat Service down)

**Add Webhook Retry + Acknowledgment:**

```
GETSTREAM->>CHAT: POST /webhooks/call-ended
[Chat Service down, returns 503]
GETSTREAM: Retry in 10s (exponential backoff)
GETSTREAM->>CHAT: POST /webhooks/call-ended (retry 1)
CHAT->>PGMASTER: Update call record
CHAT-->>GETSTREAM: 200 OK (acknowledge)
GETSTREAM: Stop retrying
```

**Add Webhook Queue (more robust):**

```
GETSTREAM->>APIGW: POST /webhooks/call-ended
APIGW->>RABBIT: Queue webhook payload
APIGW-->>GETSTREAM: 200 OK (immediate ACK)

[Background]
RABBIT->>CHAT: Process webhook
CHAT->>PGMASTER: Update call record
[If fails, RabbitMQ retries]
```

---

## **System Design Checklist for MVP** ✅

**Before Writing Code:**
- [ ] Switch Redis Pub/Sub → Redis Streams
- [ ] Add WS Gateway connection registry in Redis
- [ ] Configure RabbitMQ Dead Letter Queues
- [ ] Add health check endpoints to all services
- [ ] Set service-to-service timeouts (3s default)

**Before Beta Launch:**
- [ ] Monitor database replication lag
- [ ] Add circuit breakers between services
- [ ] Implement webhook retry logic
- [ ] Set up media processing status tracking
- [ ] Configure CDN cache purge/busting

**Before Production:**
- [ ] Load test Redis Cluster failover
- [ ] Test RabbitMQ job retry scenarios
- [ ] Verify WebSocket reconnection works
- [ ] Test database failover (master crash)
- [ ] Confirm load balancer health checks

---

## **Updated Flow Recommendations**

**Add these to your diagrams:**

1. **Health Check Flow:**
```
Note over LB,APIGW: Health checks every 5s<br/>Unhealthy instances removed
```

2. **Failover Flow:**
```
Note over PGMASTER,PGREPLICA: Replication lag monitored<br/>Auto-failover if master down
```

3. **Circuit Breaker:**
```
Note over APIGW,CHAT: Timeout: 3s<br/>Circuit breaker on failures
```

4. **Webhook Reliability:**
```
GETSTREAM->>APIGW: Webhook
APIGW->>RABBIT: Queue webhook (reliable)
RABBIT->>CHAT: Process async
```

These are all **infrastructure/system-level** concerns - no data model changes needed. Focus on these and your system will be solid! 🚀