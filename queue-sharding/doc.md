# Queue Sharding Documentation

## Overview

Queue sharding is a technique for distributing message processing across multiple queues to achieve both **scalability** and **ordering guarantees**. Instead of using a single queue where multiple consumers might process messages out of order, sharding partitions messages into multiple queues based on a consistent hash, ensuring that related messages maintain their order while enabling parallel processing.

## Architecture

### Shard Distribution

The system creates **N** shard queues instead of one monolithic queue:

```
chat.message.notify.0
chat.message.notify.1
chat.message.notify.2
...
chat.message.notify.(N-1)
```

Where `N` is defined by the `CHAT_NOTIFY_SHARDS` configuration parameter.

## How It Works

### 1. Shard Selection (Publisher Side)

When a message event occurs, the publisher determines which shard queue to use by computing:

```
shard = hash(conversation_id) mod N
```

**Implementation Details:**
- Uses FNV-1a hash algorithm for stable, deterministic hashing
- The `conversation_id` is used as the sharding key
- Same `conversation_id` always maps to the same shard queue
- Different conversations are distributed across all available shards

**Benefits:**
- Consistent routing: all messages for a given conversation go to the same queue
- Load distribution: conversations are spread across shards for parallelism
- Predictable behavior: hash function ensures deterministic shard assignment

### 2. Consumer Architecture

On service startup, the system initializes:

- **N AMQP channels** (one dedicated channel per shard)
- **N goroutines** (one consumer goroutine per shard)
- Each goroutine consumes from exactly one queue: `chat.message.notify.<shard>`

**Why This Design:**
- AMQP channels are not goroutine-safe, requiring dedicated channels per consumer
- Clean partitioning prevents concurrency issues
- Each shard operates independently for better isolation

### 3. Ordering Guarantees

**Key Principle:** RabbitMQ guarantees FIFO (First-In-First-Out) order within a single queue.

**What You Get:**
- ✅ **Per-conversation ordering**: Since all events for a given `conversation_id` route to the same shard queue, message order is preserved for that conversation
- ✅ **Parallel processing**: Multiple shard queues process different conversations simultaneously
- ✅ **Higher throughput**: N parallel consumers instead of one

**What You Don't Get (by design):**
- ❌ Ordering across different conversations (typically not required)

### 4. Performance Tuning

The sharding behavior is controlled by two environment variables:

#### `CHAT_NOTIFY_SHARDS`

Defines the number of shard queues and consumers.

- **Value: `1`** → Single queue mode (no sharding, original behavior)
- **Value: `8`** → 8 shard queues with 8 parallel consumers
- **Recommended:** Start with 4-8 shards, adjust based on load

#### `CHAT_NOTIFY_PREFETCH`

Controls how many unacknowledged messages each consumer can buffer.

- Higher values improve throughput by reducing idle time
- Lower values provide better load distribution under variable processing times
- **Recommended:** Start with 50-100, monitor and adjust

**Example Configuration:**

```bash
export CHAT_NOTIFY_SHARDS=8
export CHAT_NOTIFY_PREFETCH=100
make air
```

## Design Comparison

### Without Sharding (Single Queue)

```
[Messages] → [Single Queue] → [Consumer(s)]
```

**Characteristics:**
- Single point of contention
- Easy bottleneck under high load
- Multiple consumers cause ordering issues
- Simpler to reason about

### With Sharding (Multiple Queues)

```
[Messages] → [Hash Router] → [Queue 0] → [Consumer 0]
                           → [Queue 1] → [Consumer 1]
                           → [Queue 2] → [Consumer 2]
                           → [Queue N] → [Consumer N]
```

**Characteristics:**
- Distributed load across N queues
- Parallel processing with maintained ordering
- Scalable throughput
- Per-conversation ordering preserved

## Best Practices

1. **Choose shard count carefully**: More shards = more parallelism, but also more overhead. Start with 4-8 for most workloads.

2. **Monitor shard distribution**: Ensure conversations are evenly distributed. Skewed distributions may indicate poor hash characteristics or uneven conversation activity.

3. **Set appropriate prefetch**: Balance between throughput (higher prefetch) and fair distribution (lower prefetch).

4. **Consider conversation lifetime**: Long-lived conversations benefit more from sharding than short-lived ones.

5. **Test ordering requirements**: Verify that per-conversation ordering meets your application's needs.

## Limitations

- Ordering is only guaranteed within a single conversation, not globally
- Shard count should be decided at deployment time; changing it requires careful migration
- Uneven conversation activity can lead to unbalanced shard utilization
- Memory overhead increases with number of shards (N channels, N goroutines)