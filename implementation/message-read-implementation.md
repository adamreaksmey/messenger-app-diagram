I'll draft a complete implementation for message read receipts using your existing schema.

## 1. Database Schema Enhancements

### PostgreSQL Migration
```sql
-- Add index for faster lookups
CREATE INDEX idx_message_reads_conversation_user 
ON MESSAGE_READS(conversation_id, user_id);

CREATE INDEX idx_conversations_last_message 
ON CONVERSATIONS(last_message_at DESC);

-- Enhance MESSAGE_DELIVERIES_MONGO status enum to include 'read'
-- This will be done in application code since it's MongoDB
```

### MongoDB Indexes
```javascript
// Add compound indexes for efficient queries
db.messages.createIndex({ 
  conversation_id: 1, 
  sequence_number: -1, 
  created_at: -1 
});

db.message_deliveries.createIndex({ 
  message_id: 1, 
  user_id: 1 
}, { unique: true });
```

## 2. Backend API Implementation

### File: `src/services/MessageService.js`

```javascript
class MessageService {
  constructor(pgPool, mongoClient) {
    this.pg = pgPool;
    this.mongo = mongoClient.db('chat').collection('messages');
    this.deliveries = mongoClient.db('chat').collection('message_deliveries');
  }

  /**
   * Fetch messages with read status for a conversation
   */
  async getMessagesWithReadStatus(conversationId, currentUserId, limit = 50, beforeSequence = null) {
    // Step 1: Get conversation details and recipient's read position
    const conversationData = await this.getConversationReadData(conversationId, currentUserId);
    
    if (!conversationData) {
      throw new Error('Conversation not found');
    }

    // Step 2: Fetch messages from MongoDB
    const query = {
      conversation_id: conversationId,
      is_deleted: false
    };

    if (beforeSequence) {
      query.sequence_number = { $lt: beforeSequence };
    }

    const messages = await this.mongo
      .find(query)
      .sort({ sequence_number: -1 })
      .limit(limit)
      .toArray();

    // Step 3: Enrich messages with read status
    const enrichedMessages = messages.map(msg => 
      this.enrichMessageWithReadStatus(
        msg, 
        currentUserId, 
        conversationData.recipientReadPosition
      )
    );

    return {
      messages: enrichedMessages,
      conversation: conversationData.conversation,
      recipient_read_position: conversationData.recipientReadPosition,
      has_more: messages.length === limit
    };
  }

  /**
   * Get conversation details and recipient's read position
   */
  async getConversationReadData(conversationId, currentUserId) {
    const query = `
      SELECT 
        c.conversation_id,
        c.type,
        c.user1_id,
        c.user2_id,
        c.group_id,
        c.last_message_at,
        c.last_message_preview,
        CASE 
          WHEN c.user1_id = $2 THEN c.unread_count_user1
          ELSE c.unread_count_user2
        END as my_unread_count,
        -- Get recipient user ID for direct chats
        CASE 
          WHEN c.type = 'direct' AND c.user1_id = $2 THEN c.user2_id
          WHEN c.type = 'direct' AND c.user2_id = $2 THEN c.user1_id
          ELSE NULL
        END as recipient_user_id,
        -- Get recipient's read position
        mr.last_read_sequence_number as recipient_last_read_sequence,
        mr.read_at as recipient_read_at
      FROM CONVERSATIONS c
      LEFT JOIN MESSAGE_READS mr ON 
        mr.conversation_id = c.conversation_id 
        AND mr.user_id = CASE 
          WHEN c.type = 'direct' AND c.user1_id = $2 THEN c.user2_id
          WHEN c.type = 'direct' AND c.user2_id = $2 THEN c.user1_id
          ELSE NULL
        END
      WHERE c.conversation_id = $1
        AND (
          c.user1_id = $2 
          OR c.user2_id = $2 
          OR EXISTS (
            SELECT 1 FROM GROUP_MEMBERS gm 
            WHERE gm.group_id = c.group_id 
              AND gm.user_id = $2 
              AND gm.left_at IS NULL
          )
        )
    `;

    const result = await this.pg.query(query, [conversationId, currentUserId]);
    
    if (result.rows.length === 0) {
      return null;
    }

    const row = result.rows[0];

    return {
      conversation: {
        conversation_id: row.conversation_id,
        type: row.type,
        last_message_at: row.last_message_at,
        last_message_preview: row.last_message_preview,
        my_unread_count: row.my_unread_count
      },
      recipientReadPosition: row.recipient_last_read_sequence ? {
        user_id: row.recipient_user_id,
        last_read_sequence_number: row.recipient_last_read_sequence,
        read_at: row.recipient_read_at
      } : null
    };
  }

  /**
   * Enrich a single message with read status
   */
  enrichMessageWithReadStatus(message, currentUserId, recipientReadPosition) {
    const enriched = {
      message_id: message._id.toString(),
      conversation_id: message.conversation_id,
      sender_id: message.sender_id,
      message_type: message.message_type,
      content: message.content,
      media_ids: message.media_ids,
      reply_to_message_id: message.reply_to_message_id?.toString(),
      metadata: message.metadata,
      mentions: message.mentions,
      sequence_number: message.sequence_number,
      created_at: message.created_at,
      edited_at: message.edited_at,
      is_deleted: message.is_deleted
    };

    // Only add read status for messages sent by current user
    if (message.sender_id === currentUserId) {
      enriched.read_status = this.determineReadStatus(
        message.sequence_number,
        recipientReadPosition
      );
      
      if (enriched.read_status === 'read' && recipientReadPosition) {
        enriched.read_at = recipientReadPosition.read_at;
      }
    } else {
      enriched.read_status = null;
      enriched.read_at = null;
    }

    return enriched;
  }

  /**
   * Determine read status based on sequence numbers
   */
  determineReadStatus(messageSequence, recipientReadPosition) {
    if (!recipientReadPosition) {
      return 'sent';
    }

    if (messageSequence <= recipientReadPosition.last_read_sequence_number) {
      return 'read';
    }

    return 'delivered';
  }

  /**
   * Update user's read position in a conversation
   */
  async updateReadPosition(conversationId, userId, lastReadMessageId, lastReadSequenceNumber) {
    const client = await this.pg.connect();
    
    try {
      await client.query('BEGIN');

      // Upsert MESSAGE_READS
      const readQuery = `
        INSERT INTO MESSAGE_READS (
          id,
          conversation_id,
          user_id,
          last_read_message_id,
          last_read_sequence_number,
          read_at
        ) VALUES (
          gen_random_uuid(),
          $1,
          $2,
          $3,
          $4,
          NOW()
        )
        ON CONFLICT (conversation_id, user_id) 
        DO UPDATE SET
          last_read_message_id = EXCLUDED.last_read_message_id,
          last_read_sequence_number = EXCLUDED.last_read_sequence_number,
          read_at = EXCLUDED.read_at
        RETURNING last_read_sequence_number, read_at;
      `;

      const readResult = await client.query(readQuery, [
        conversationId,
        userId,
        lastReadMessageId,
        lastReadSequenceNumber
      ]);

      // Update unread count in CONVERSATIONS
      const unreadQuery = `
        UPDATE CONVERSATIONS
        SET 
          unread_count_user1 = CASE WHEN user1_id = $2 THEN 0 ELSE unread_count_user1 END,
          unread_count_user2 = CASE WHEN user2_id = $2 THEN 0 ELSE unread_count_user2 END
        WHERE conversation_id = $1
        RETURNING user1_id, user2_id, type, group_id;
      `;

      const convResult = await client.query(unreadQuery, [conversationId, userId]);

      await client.query('COMMIT');

      // Get the other participant(s) to notify
      const conversation = convResult.rows[0];
      let recipientIds = [];

      if (conversation.type === 'direct') {
        recipientIds = [
          conversation.user1_id === userId ? conversation.user2_id : conversation.user1_id
        ];
      } else if (conversation.type === 'group') {
        // For groups, get all active members except the reader
        const membersQuery = `
          SELECT user_id 
          FROM GROUP_MEMBERS 
          WHERE group_id = $1 
            AND user_id != $2 
            AND left_at IS NULL
        `;
        const membersResult = await this.pg.query(membersQuery, [conversation.group_id, userId]);
        recipientIds = membersResult.rows.map(r => r.user_id);
      }

      return {
        conversation_id: conversationId,
        user_id: userId,
        last_read_sequence_number: readResult.rows[0].last_read_sequence_number,
        read_at: readResult.rows[0].read_at,
        recipient_ids: recipientIds
      };

    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Send a new message
   */
  async sendMessage(conversationId, senderId, messageData) {
    const client = await this.pg.connect();
    
    try {
      await client.query('BEGIN');

      // Get next sequence number
      const seqQuery = `
        INSERT INTO CONVERSATION_SEQUENCES (conversation_id, sequence_number)
        VALUES ($1, 1)
        ON CONFLICT (conversation_id) 
        DO UPDATE SET sequence_number = CONVERSATION_SEQUENCES.sequence_number + 1
        RETURNING sequence_number;
      `;
      
      const seqResult = await client.query(seqQuery, [conversationId]);
      const sequenceNumber = seqResult.rows[0].sequence_number;

      // Insert message in MongoDB
      const message = {
        conversation_id: conversationId,
        sender_id: senderId,
        message_type: messageData.message_type || 'text',
        content: messageData.content,
        reply_to_message_id: messageData.reply_to_message_id,
        media_ids: messageData.media_ids || [],
        metadata: messageData.metadata || {},
        mentions: messageData.mentions || [],
        sequence_number: sequenceNumber,
        created_at: new Date(),
        edited_at: null,
        deleted_at: null,
        is_deleted: false
      };

      const insertResult = await this.mongo.insertOne(message);
      const messageId = insertResult.insertedId;

      // Update CONVERSATIONS table
      const updateConvQuery = `
        UPDATE CONVERSATIONS
        SET 
          last_message_id = $2,
          last_message_at = $3,
          last_message_preview = $4,
          unread_count_user1 = CASE 
            WHEN user1_id != $5 THEN unread_count_user1 + 1 
            ELSE unread_count_user1 
          END,
          unread_count_user2 = CASE 
            WHEN user2_id != $5 THEN unread_count_user2 + 1 
            ELSE unread_count_user2 
          END
        WHERE conversation_id = $1
        RETURNING user1_id, user2_id, type, group_id;
      `;

      const preview = this.generateMessagePreview(message);
      const convResult = await client.query(updateConvQuery, [
        conversationId,
        messageId.toString(),
        message.created_at,
        preview,
        senderId
      ]);

      await client.query('COMMIT');

      // Get recipient IDs for notifications
      const conversation = convResult.rows[0];
      let recipientIds = [];

      if (conversation.type === 'direct') {
        recipientIds = [
          conversation.user1_id === senderId ? conversation.user2_id : conversation.user1_id
        ];
      } else if (conversation.type === 'group') {
        const membersQuery = `
          SELECT user_id 
          FROM GROUP_MEMBERS 
          WHERE group_id = $1 
            AND user_id != $2 
            AND left_at IS NULL
        `;
        const membersResult = await this.pg.query(membersQuery, [conversation.group_id, senderId]);
        recipientIds = membersResult.rows.map(r => r.user_id);
      }

      // Create delivery records
      await this.createDeliveryRecords(messageId, recipientIds);

      message._id = messageId;
      message.read_status = 'sent';

      return {
        message,
        recipient_ids: recipientIds
      };

    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Create delivery records for message recipients
   */
  async createDeliveryRecords(messageId, recipientIds) {
    const deliveries = recipientIds.map(userId => ({
      message_id: messageId,
      user_id: userId,
      status: 'sent',
      delivered_at: null,
      error_message: null
    }));

    if (deliveries.length > 0) {
      await this.deliveries.insertMany(deliveries);
    }
  }

  /**
   * Mark message as delivered
   */
  async markMessageDelivered(messageId, userId) {
    await this.deliveries.updateOne(
      { message_id: messageId, user_id: userId },
      { 
        $set: { 
          status: 'delivered',
          delivered_at: new Date()
        }
      }
    );
  }

  /**
   * Generate message preview for conversation list
   */
  generateMessagePreview(message) {
    if (message.message_type === 'text') {
      return message.content?.substring(0, 100) || '';
    }
    
    const typeLabels = {
      image: '📷 Photo',
      video: '🎥 Video',
      audio: '🎵 Audio',
      file: '📎 File',
      location: '📍 Location',
      contact: '👤 Contact',
      sticker: 'Sticker'
    };
    
    return typeLabels[message.message_type] || 'Message';
  }

  /**
   * Get read count for a message in group chat
   */
  async getMessageReadCount(conversationId, groupId, messageSequenceNumber, senderId) {
    const query = `
      SELECT COUNT(DISTINCT mr.user_id) as read_count
      FROM MESSAGE_READS mr
      JOIN GROUP_MEMBERS gm ON gm.user_id = mr.user_id 
      WHERE mr.conversation_id = $1
        AND gm.group_id = $2
        AND gm.left_at IS NULL
        AND mr.last_read_sequence_number >= $3
        AND mr.user_id != $4;
    `;

    const result = await this.pg.query(query, [
      conversationId,
      groupId,
      messageSequenceNumber,
      senderId
    ]);

    return parseInt(result.rows[0].read_count);
  }

  /**
   * Get list of users who read a message in group chat
   */
  async getMessageReadBy(conversationId, groupId, messageSequenceNumber, senderId, limit = 20) {
    const query = `
      SELECT 
        u.user_id, 
        u.display_name, 
        u.avatar_url, 
        mr.read_at
      FROM MESSAGE_READS mr
      JOIN USERS u ON u.user_id = mr.user_id
      JOIN GROUP_MEMBERS gm ON gm.user_id = mr.user_id
      WHERE mr.conversation_id = $1
        AND gm.group_id = $2
        AND gm.left_at IS NULL
        AND mr.last_read_sequence_number >= $3
        AND mr.user_id != $4
      ORDER BY mr.read_at ASC
      LIMIT $5;
    `;

    const result = await this.pg.query(query, [
      conversationId,
      groupId,
      messageSequenceNumber,
      senderId,
      limit
    ]);

    return result.rows;
  }
}

module.exports = MessageService;
```

## 3. API Routes

### File: `src/routes/messages.js`

```javascript
const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');

module.exports = (messageService, webSocketService) => {
  /**
   * GET /api/conversations/:conversationId/messages
   * Fetch messages with read status
   */
  router.get('/conversations/:conversationId/messages', authenticateToken, async (req, res) => {
    try {
      const { conversationId } = req.params;
      const { before_sequence, limit = 50 } = req.query;
      const userId = req.user.user_id;

      const result = await messageService.getMessagesWithReadStatus(
        conversationId,
        userId,
        parseInt(limit),
        before_sequence ? parseInt(before_sequence) : null
      );

      res.json(result);
    } catch (error) {
      console.error('Error fetching messages:', error);
      res.status(500).json({ error: 'Failed to fetch messages' });
    }
  });

  /**
   * POST /api/conversations/:conversationId/messages
   * Send a new message
   */
  router.post('/conversations/:conversationId/messages', authenticateToken, async (req, res) => {
    try {
      const { conversationId } = req.params;
      const userId = req.user.user_id;
      const messageData = req.body;

      const result = await messageService.sendMessage(
        conversationId,
        userId,
        messageData
      );

      // Send via WebSocket to recipients
      result.recipient_ids.forEach(recipientId => {
        webSocketService.sendToUser(recipientId, {
          type: 'new_message',
          conversation_id: conversationId,
          message: result.message
        });
      });

      res.status(201).json(result.message);
    } catch (error) {
      console.error('Error sending message:', error);
      res.status(500).json({ error: 'Failed to send message' });
    }
  });

  /**
   * POST /api/conversations/:conversationId/read
   * Mark messages as read
   */
  router.post('/conversations/:conversationId/read', authenticateToken, async (req, res) => {
    try {
      const { conversationId } = req.params;
      const userId = req.user.user_id;
      const { last_read_message_id, last_read_sequence_number } = req.body;

      if (!last_read_message_id || !last_read_sequence_number) {
        return res.status(400).json({ 
          error: 'last_read_message_id and last_read_sequence_number are required' 
        });
      }

      const result = await messageService.updateReadPosition(
        conversationId,
        userId,
        last_read_message_id,
        last_read_sequence_number
      );

      // Notify sender(s) via WebSocket
      result.recipient_ids.forEach(recipientId => {
        webSocketService.sendToUser(recipientId, {
          type: 'message_read',
          conversation_id: conversationId,
          user_id: userId,
          last_read_sequence_number: result.last_read_sequence_number,
          read_at: result.read_at
        });
      });

      res.json({ 
        success: true,
        last_read_sequence_number: result.last_read_sequence_number,
        read_at: result.read_at
      });
    } catch (error) {
      console.error('Error updating read position:', error);
      res.status(500).json({ error: 'Failed to update read position' });
    }
  });

  /**
   * POST /api/messages/:messageId/delivered
   * Mark message as delivered
   */
  router.post('/messages/:messageId/delivered', authenticateToken, async (req, res) => {
    try {
      const { messageId } = req.params;
      const userId = req.user.user_id;

      await messageService.markMessageDelivered(messageId, userId);

      res.json({ success: true });
    } catch (error) {
      console.error('Error marking message delivered:', error);
      res.status(500).json({ error: 'Failed to mark message delivered' });
    }
  });

  /**
   * GET /api/conversations/:conversationId/messages/:sequenceNumber/read-by
   * Get who read a message (for group chats)
   */
  router.get('/conversations/:conversationId/messages/:sequenceNumber/read-by', 
    authenticateToken, 
    async (req, res) => {
      try {
        const { conversationId, sequenceNumber } = req.params;
        const userId = req.user.user_id;
        const { limit = 20 } = req.query;

        // Get conversation to verify it's a group and get group_id
        const convQuery = `
          SELECT type, group_id 
          FROM CONVERSATIONS 
          WHERE conversation_id = $1
        `;
        const convResult = await messageService.pg.query(convQuery, [conversationId]);
        
        if (convResult.rows.length === 0) {
          return res.status(404).json({ error: 'Conversation not found' });
        }

        const conversation = convResult.rows[0];
        
        if (conversation.type !== 'group') {
          return res.status(400).json({ error: 'Only available for group chats' });
        }

        const readCount = await messageService.getMessageReadCount(
          conversationId,
          conversation.group_id,
          parseInt(sequenceNumber),
          userId
        );

        const readBy = await messageService.getMessageReadBy(
          conversationId,
          conversation.group_id,
          parseInt(sequenceNumber),
          userId,
          parseInt(limit)
        );

        res.json({
          read_count: readCount,
          read_by: readBy
        });
      } catch (error) {
        console.error('Error fetching read-by info:', error);
        res.status(500).json({ error: 'Failed to fetch read-by info' });
      }
    }
  );

  return router;
};
```

## 4. WebSocket Handler

### File: `src/services/WebSocketService.js`

```javascript
class WebSocketService {
  constructor() {
    this.connections = new Map(); // userId -> Set of WebSocket connections
  }

  /**
   * Register a user connection
   */
  addConnection(userId, ws) {
    if (!this.connections.has(userId)) {
      this.connections.set(userId, new Set());
    }
    this.connections.get(userId).add(ws);

    ws.on('close', () => {
      this.removeConnection(userId, ws);
    });
  }

  /**
   * Remove a user connection
   */
  removeConnection(userId, ws) {
    const userConnections = this.connections.get(userId);
    if (userConnections) {
      userConnections.delete(ws);
      if (userConnections.size === 0) {
        this.connections.delete(userId);
      }
    }
  }

  /**
   * Send message to a specific user (all their devices)
   */
  sendToUser(userId, data) {
    const userConnections = this.connections.get(userId);
    if (userConnections) {
      const message = JSON.stringify(data);
      userConnections.forEach(ws => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(message);
        }
      });
    }
  }

  /**
   * Send message to multiple users
   */
  sendToUsers(userIds, data) {
    userIds.forEach(userId => {
      this.sendToUser(userId, data);
    });
  }
}

module.exports = WebSocketService;
```

## 5. Client-Side Implementation

### File: `client/src/services/MessageService.js`

```javascript
class MessageService {
  constructor(apiClient, wsClient) {
    this.api = apiClient;
    this.ws = wsClient;
    this.readDebounceTimers = new Map();
  }

  /**
   * Fetch messages for a conversation
   */
  async fetchMessages(conversationId, beforeSequence = null, limit = 50) {
    const params = new URLSearchParams({ limit: limit.toString() });
    if (beforeSequence) {
      params.append('before_sequence', beforeSequence.toString());
    }

    const response = await this.api.get(
      `/conversations/${conversationId}/messages?${params}`
    );
    return response.data;
  }

  /**
   * Send a message
   */
  async sendMessage(conversationId, messageData) {
    const response = await this.api.post(
      `/conversations/${conversationId}/messages`,
      messageData
    );
    return response.data;
  }

  /**
   * Mark messages as read (debounced)
   */
  markAsRead(conversationId, lastReadMessageId, lastReadSequenceNumber) {
    // Clear existing timer for this conversation
    if (this.readDebounceTimers.has(conversationId)) {
      clearTimeout(this.readDebounceTimers.get(conversationId));
    }

    // Set new timer
    const timer = setTimeout(async () => {
      try {
        await this.api.post(`/conversations/${conversationId}/read`, {
          last_read_message_id: lastReadMessageId,
          last_read_sequence_number: lastReadSequenceNumber
        });
        this.readDebounceTimers.delete(conversationId);
      } catch (error) {
        console.error('Error marking messages as read:', error);
      }
    }, 1000); // 1 second debounce

    this.readDebounceTimers.set(conversationId, timer);
  }

  /**
   * Mark message as delivered
   */
  async markDelivered(messageId) {
    try {
      await this.api.post(`/messages/${messageId}/delivered`);
    } catch (error) {
      console.error('Error marking message delivered:', error);
    }
  }

  /**
   * Get read-by info for group message
   */
  async getMessageReadBy(conversationId, sequenceNumber, limit = 20) {
    const response = await this.api.get(
      `/conversations/${conversationId}/messages/${sequenceNumber}/read-by?limit=${limit}`
    );
    return response.data;
  }

  /**
   * Subscribe to real-time message updates
   */
  subscribeToMessages(conversationId, callbacks) {
    const handlers = {
      new_message: (data) => {
        if (data.conversation_id === conversationId && callbacks.onNewMessage) {
          callbacks.onNewMessage(data.message);
        }
      },
      message_read: (data) => {
        if (data.conversation_id === conversationId && callbacks.onMessageRead) {
          callbacks.onMessageRead({
            user_id: data.user_id,
            last_read_sequence_number: data.last_read_sequence_number,
            read_at: data.read_at
          });
        }
      }
    };

    // Register handlers
    Object.entries(handlers).forEach(([event, handler]) => {
      this.ws.on(event, handler);
    });

    // Return cleanup function
    return () => {
      Object.entries(handlers).forEach(([event, handler]) => {
        this.ws.off(event, handler);
      });
    };
  }
}

export default MessageService;
```

### File: `client/src/components/Message.jsx`

```jsx
import React from 'react';
import { Check, CheckCheck, Clock } from 'lucide-react';

const Message = ({ message, currentUserId, isGroupChat }) => {
  const isSentByMe = message.sender_id === currentUserId;

  const renderReadStatus = () => {
    if (!isSentByMe || !message.read_status) {
      return null;
    }

    switch (message.read_status) {
      case 'sending':
        return <Clock className="w-4 h-4 text-gray-400" />;
      case 'sent':
        return <Check className="w-4 h-4 text-gray-400" />;
      case 'delivered':
        return <CheckCheck className="w-4 h-4 text-gray-400" />;
      case 'read':
        return <CheckCheck className="w-4 h-4 text-blue-500" />;
      default:
        return null;
    }
  };

  const formatTime = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { 
      hour: '2-digit', 
      minute: '2-digit' 
    });
  };

  return (
    <div className={`flex ${isSentByMe ? 'justify-end' : 'justify-start'} mb-2`}>
      <div
        className={`max-w-[70%] rounded-lg px-4 py-2 ${
          isSentByMe
            ? 'bg-blue-500 text-white'
            : 'bg-gray-200 text-gray-900'
        }`}
      >
        {message.reply_to_message_id && (
          <div className="text-xs opacity-75 mb-1 border-l-2 pl-2">
            Reply to message
          </div>
        )}
        
        <div className="whitespace-pre-wrap break-words">
          {message.content}
        </div>

        {message.media_ids && message.media_ids.length > 0 && (
          <div className="mt-2">
            {/* Render media attachments */}
          </div>
        )}

        <div className="flex items-center justify-end gap-1 mt-1">
          <span className="text-xs opacity-75">
            {formatTime(message.created_at)}
          </span>
          {renderReadStatus()}
        </div>

        {message.edited_at && (
          <div className="text-xs opacity-75 mt-1">
            Edited
          </div>
        )}
      </div>
    </div>
  );
};

export default Message;
```

### File: `client/src/components/ChatWindow.jsx`

```jsx
import React, { useState, useEffect, useRef } from 'react';
import Message from './Message';
import MessageService from '../services/MessageService';

const ChatWindow = ({ 
  conversationId, 
  currentUserId, 
  messageService 
}) => {
  const [messages, setMessages] = useState([]);
  const [recipientReadPosition, setRecipientReadPosition] = useState(null);
  const [loading, setLoading] = useState(true);
  const [hasMore, setHasMore] = useState(true);
  const messagesEndRef = useRef(null);
  const chatContainerRef = useRef(null);

  useEffect(() => {
    loadMessages();

    // Subscribe to real-time updates
    const unsubscribe = messageService.subscribeToMessages(conversationId, {
      onNewMessage: handleNewMessage,
      onMessageRead: handleMessageRead
    });

    return () => {
      unsubscribe();
    };
  }, [conversationId]);

  const loadMessages = async (beforeSequence = null) => {
    try {
      setLoading(true);
      const data = await messageService.fetchMessages(
        conversationId, 
        beforeSequence
      );

      if (beforeSequence) {
        setMessages(prev => [...data.messages, ...prev]);
      } else {
        setMessages(data.messages.reverse());
        scrollToBottom();
      }

      setRecipientReadPosition(data.recipient_read_position);
      setHasMore(data.has_more);
    } catch (error) {
      console.error('Error loading messages:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleNewMessage = (newMessage) => {
    setMessages(prev => [...prev, newMessage]);
    scrollToBottom();

    // Mark as delivered if not sent by current user
    if (newMessage.sender_id !== currentUserId) {
      messageService.markDelivered(newMessage.message_id);
    }
  };

  const handleMessageRead = (readData) => {
    // Update recipient read position
    setRecipientReadPosition(readData);

    // Update read status for affected messages
    setMessages(prev => prev.map(msg => {
      if (msg.sender_id === currentUserId && 
          msg.sequence_number <= readData.last_read_sequence_number) {
        return {
          ...msg,
          read_status: 'read',
          read_at: readData.read_at
        };
      }
      return msg;
    }));
  };

  const handleScroll = () => {
    const container = chatContainerRef.current;
    if (!container) return;

    // Load more messages when scrolled to top
    if (container.scrollTop === 0 && hasMore && !loading) {
      const firstMessage = messages[0];
      if (firstMessage) {
        loadMessages(firstMessage.sequence_number);
      }
    }

    // Mark messages as read when scrolled into view
    const lastVisibleMessage = getLastVisibleMessage();
    if (lastVisibleMessage && lastVisibleMessage.sender_id !== currentUserId) {
      messageService.markAsRead(
        conversationId,
        lastVisibleMessage.message_id,
        lastVisibleMessage.sequence_number
      );
    }
  };

  const getLastVisibleMessage = () => {
    const container = chatContainerRef.current;
    if (!container) return null;

    const containerRect = container.getBoundingClientRect();
    
    // Find the last message that's fully visible
    for (let i = messages.length - 1; i >= 0; i--) {
      const messageElement = document.getElementById(`message-${messages[i].message_id}`);
      if (messageElement) {
        const rect = messageElement.getBoundingClientRect();
        if (rect.bottom <= containerRect.bottom) {
          return messages[i];
        }
      }
    }
    
    return null;
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const handleSendMessage = async (content) => {
    try {
      await messageService.sendMessage(conversationId, {
        message_type: 'text',
        content: content
      });
    } catch (error) {
      console.error('Error sending message:', error);
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div 
        ref={chatContainerRef}
        className="flex-1 overflow-y-auto p-4"
        onScroll={handleScroll}
      >
        {loading && messages.length === 0 ? (
          <div className="flex justify-center py-4">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
          </div>
        ) : (
          <>
            {messages.map(message => (
              <div key={message.message_id} id={`message-${message.message_id}`}>
                <Message
                  message={message}
                  currentUserId={currentUserId}
                />
              </div>
            ))}
            <div ref={messagesEndRef} />
          </>
        )}
      </div>

      <MessageInput onSend={handleSendMessage} />
    </div>
  );
};

export default ChatWindow;
```

## 6. Testing Example

### File: `tests/message-reads.test.js`

```javascript
const { expect } = require('chai');
const MessageService = require('../src/services/MessageService');

describe('Message Read Receipts', () => {
  let messageService;
  let testConversationId;
  let user1Id, user2Id;

  before(async () => {
    // Setup test database and service
    // ... initialization code
  });

  it('should update read position', async () => {
    const result = await messageService.updateReadPosition(
      testConversationId,
      user2Id,
      'message123',
      100
    );

    expect(result.last_read_sequence_number).to.equal(100);
    expect(result.recipient_ids).to.include(user1Id);
  });

  it('should fetch messages with correct read status', async () => {
    // Send message from user1
    await messageService.sendMessage(testConversationId, user1Id, {
      message_type: 'text',
      content: 'Hello'
    });

    // Fetch as user1 (sender)
    const result = await messageService.getMessagesWithReadStatus(
      testConversationId,
      user1Id
    );

    const sentMessage = result.messages[0];
    expect(sentMessage.read_status).to.equal('sent');

    // User2 reads the message
    await messageService.updateReadPosition(
      testConversationId,
      user2Id,
      sentMessage.message_id,
      sentMessage.sequence_number
    );

    // Fetch again as user1
    const updatedResult = await messageService.getMessagesWithReadStatus(
      testConversationId,
      user1Id
    );

    const readMessage = updatedResult.messages[0];
    expect(readMessage.read_status).to.equal('read');
  });

  it('should get read count for group messages', async () => {
    // Setup group conversation
    // ... create group and add members

    const count = await messageService.getMessageReadCount(
      groupConversationId,
      groupId,
      50,
      user1Id
    );

    expect(count).to.be.a('number');
  });
});
```

This implementation provides:
- ✅ Read receipts for direct chats (like Telegram)
- ✅ Read counts for group chats
- ✅ Real-time updates via WebSocket
- ✅ Efficient database queries
- ✅ Debounced read position updates
- ✅ Clean separation of concerns
- ✅ React components with proper state management

The system uses your existing `MESSAGE_READS` table and works seamlessly with both PostgreSQL and MongoDB!