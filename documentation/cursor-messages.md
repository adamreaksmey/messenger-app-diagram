
## **Mobile-Backend Contract (Document This)**

**Endpoint:** `GET /messages/{conversation_id}`

**Parameters:**

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `limit` | int | No | Max messages to return (default: 50, max: 500) |
| `last_time_stamp` | ISO8601 | No | Cursor timestamp for pagination |
| `last_message_id` | string | No | Tiebreaker for messages with same timestamp |
| `direction` | string | No | `newer` (sync) or `older` (scroll up). Default: `newer` if timestamp provided, `older` if not |

**Use Cases:**

| Scenario | Parameters | Returns |
|----------|------------|---------|
| Initial load | `limit=50` | Latest 50 messages (DESC) |
| Sync after offline | `last_time_stamp=<latest>&direction=newer` | Messages after timestamp (ASC) |
| Scroll up (load older) | `last_time_stamp=<oldest>&direction=older` | Messages before timestamp (DESC) |
| Pagination (legacy) | `limit=50&offset=100` | Offset-based (DESC) |