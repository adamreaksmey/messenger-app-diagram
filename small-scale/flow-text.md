## **System Overview**

This is a real-time chat application built with:
- **Frontend**: Web, Mobile, and Desktop clients
- **Backend**: Go-based microservices (Gin for REST, Gorilla WebSocket)
- **Infrastructure**: PostgreSQL, MongoDB, Redis, RabbitMQ, Aliyun OSS
- **Third-party**: GetStream.io (audio calls), Aliyun Apsara (video calls)

---

## **Core Flows Explained**

### **1. Initial Connection & Authentication (Steps 1-5)**

**Process:**
1. Client sends HTTP/WebSocket request
2. Nginx load balancer receives and routes traffic
3. REST requests → API Gateway (Gin)
4. WebSocket requests → WebSocket Gateway (Gorilla WS)
5. Gateway forwards to Auth Service for authentication

**What happens:**
- Load balancer distributes traffic across multiple server instances
- Two separate gateways handle different protocols (REST vs WebSocket)
- Auth Service validates credentials against PostgreSQL
- Sessions/tokens cached in Redis for fast subsequent validation

---

### **2. Real-Time Chat Message Flow (Steps 6-11)**

**Process:**
1. Client sends message via WebSocket
2. WebSocket Gateway receives message
3. Forwards to Chat Service
4. Chat Service persists message to MongoDB
5. Chat Service publishes to Redis Pub/Sub channel
6. Redis broadcasts to ALL WebSocket Gateway instances
7. All connected clients receive message instantly

**Why this architecture:**
- **MongoDB**: Stores chat history (flexible schema, horizontal scaling)
- **Redis Pub/Sub**: Instant fanout to thousands of connected clients
- **Multiple WS instances**: Redis ensures message reaches all server instances
- **WebSocket**: Persistent connection for sub-second message delivery

---

### **3. Background Job Processing (Steps 12-23)**

After a message is sent, Chat Service queues multiple async jobs to RabbitMQ:

**Job Types:**

**A. Push Notifications (Steps 12, 16-17)**
- Queued to RabbitMQ
- Notification Worker consumes job
- Sends via FCM (Android) / APNS (iOS)
- Notifies offline users or users in other chats

**B. Email Notifications (Steps 13, 18-19)**
- Email Worker processes queue
- Sends email for important messages
- Useful for @mentions or when user has email alerts enabled

**C. Mobile Background Delivery (Steps 14, 20-21)**
- Ensures offline mobile clients sync when they reconnect
- Background sync for battery-efficient updates

**D. Mention Detection (Steps 15, 22-23)**
- Detects @username mentions in messages
- Stores mention metadata in PostgreSQL
- Caches in Redis for fast "unread mentions" queries

**Why RabbitMQ:**
- Decouples chat delivery from slow operations (email, push notifications)
- Ensures jobs aren't lost if workers are temporarily down
- Allows independent scaling of each worker type

---

### **4. Data Layer Operations (Steps 24-31)**

**Auth Service:**
- PostgreSQL: User profiles, credentials, settings
- Redis: Session tokens, JWT cache (fast auth checks)

**Chat Service:**
- PostgreSQL: User/group metadata, relationships
- Redis: Online/offline presence, "typing..." indicators
- MongoDB: Message history

**Media Service:**
- Aliyun OSS (S3-compatible): Stores images, videos, files
- CDN: Delivers media globally with low latency
- PostgreSQL: Metadata (filename, size, owner, permissions)

---

### **5. Audio Call Flow (Steps 32-45) - GetStream.io**

**Initiation (Steps 32-38):**
1. Client requests audio call via REST API
2. Chat Service calls GetStream.io to create session
3. GetStream returns credentials + TURN/STUN servers
4. Chat Service caches call state in Redis
5. Logs call metadata to PostgreSQL
6. Returns credentials to client
7. Client establishes P2P connection with GetStream
8. Audio streaming begins

**Real-time Signaling (Steps 39-43):**
- WebSocket Gateway handles call events (ringing, answered, declined)
- Chat Service publishes status to Redis
- Redis broadcasts to all participants
- WebSocket pushes notifications (incoming call, call ended)

**Call Termination (Steps 44-46):**
- Client ends call
- GetStream sends webhook with statistics (duration, quality metrics)
- Chat Service updates PostgreSQL record
- Queues analytics job to RabbitMQ

**Why GetStream.io:**
- Specialized in real-time audio/video infrastructure
- Handles NAT traversal (TURN/STUN)
- P2P when possible, falls back to relay servers
- Provides call quality analytics

---

### **6. Video Call Flow (Steps 47-60) - Aliyun Apsara**

**Initiation (Steps 47-53):**
1. Client requests video call
2. Chat Service calls Aliyun Apsara to create video room
3. Aliyun returns room credentials + SFU server details
4. Chat Service caches state in Redis
5. Logs metadata to PostgreSQL
6. Returns credentials to client
7. Client joins video room
8. Video/audio streaming via SFU (Selective Forwarding Unit)

**Real-time Signaling (Steps 54-58):**
- Similar to audio calls
- WebSocket handles join/leave events
- Redis broadcasts participant updates
- All clients notified of room changes

**Call Termination (Steps 59-61):**
- Client leaves room
- Aliyun webhook with usage statistics
- PostgreSQL updated with final metrics
- Analytics queued to RabbitMQ

**Why Aliyun Apsara:**
- SFU architecture (more efficient than P2P for multi-party video)
- Regional optimization (likely targeting Asian markets)
- Handles encoding, adaptive bitrate, recording

**SFU vs P2P:**
- **P2P (audio)**: Each client connects directly (works for 1-on-1)
- **SFU (video)**: Server routes streams (scales to many participants)

---

## **Key Architectural Decisions**

### **Redis: Real-Time Delivery Engine**
- **Pub/Sub**: Instant message fanout to all connected clients
- **Presence**: Online/offline status, "typing..." indicators
- **Session cache**: Fast authentication without hitting database
- **Call state**: Temporary storage for active calls

### **RabbitMQ: Background Job Queue**
- **Decoupling**: Main chat flow doesn't wait for slow operations
- **Reliability**: Jobs persisted, retried on failure
- **Scalability**: Add more workers independently
- **Priority**: Different queues for urgent vs non-urgent tasks

### **Two Database Strategy**
- **PostgreSQL**: Structured data (users, groups, metadata)
- **MongoDB**: Unstructured chat messages (flexible, scales horizontally)

### **Two Gateway Strategy**
- **REST Gateway**: Stateless, easy to scale, for API calls
- **WebSocket Gateway**: Stateful connections, for real-time updates

---

## **Scalability & Reliability Features**

- **Load Balancer**: Distributes traffic, auto-scales backend
- **Redis Pub/Sub**: Handles millions of concurrent connections
- **MongoDB sharding**: Horizontally scales message storage
- **RabbitMQ**: Ensures no jobs lost, can add workers anytime
- **Multiple WS instances**: Redis ensures messages reach all servers
- **CDN**: Global media delivery with low latency
- **Microservices**: Each service scales independently