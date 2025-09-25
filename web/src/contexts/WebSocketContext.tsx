import React, { createContext, useContext, useEffect, useState } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import { wsMessageSchema, WSMessage } from '../schemas/ws';
import toast from 'react-hot-toast';

interface WebSocketContextType {
  isConnected: boolean;
  connectionStatus: 'connecting' | 'connected' | 'disconnected' | 'error';
  sendMessage: (message: any) => void;
  lastMessage: any;
}

const WebSocketContext = createContext<WebSocketContextType | null>(null);

export const useWebSocketContext = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocketContext must be used within a WebSocketProvider');
  }
  return context;
};

interface WebSocketProviderProps {
  children: React.ReactNode;
}

export const WebSocketProvider: React.FC<WebSocketProviderProps> = ({ children }) => {
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null);

  const { 
    isConnected, 
    connectionStatus, 
    sendMessage: wsSendMessage, 
    lastMessage: rawLastMessage 
  } = useWebSocket('/ws/investigations', {
    onMessage: (message) => {
      try {
        const raw = JSON.parse(message);
        const result = wsMessageSchema.safeParse(raw);
        if (!result.success) {
          console.warn('WS message failed validation', result.error.issues);
          return;
        }
        const parsedMessage = result.data;
        setLastMessage(parsedMessage);
        switch (parsedMessage.type) {
          case 'investigation_update':
            toast.success(`Investigation updated`, { duration: 2500 });
            break;
          case 'task_completed':
            toast('Task completed', { icon: '✅' });
            break;
          case 'task_failed':
            toast.error('Task failed');
            break;
          default:
            break;
        }
      } catch (e) {
        console.error('WS parse error', e);
      }
    },
    onOpen: () => {
      toast.success('🔗 Connected to OSINT Suite', {
        duration: 3000,
      });
    },
    onClose: () => {
      toast.error('📡 Disconnected from OSINT Suite', {
        duration: 3000,
      });
    },
    onError: () => {
      toast.error('❌ WebSocket connection error', {
        duration: 5000,
      });
    },
    reconnectInterval: 3000,
    maxReconnectAttempts: 5,
  });

  const sendMessage = (message: any) => {
    if (isConnected) {
      wsSendMessage(JSON.stringify(message));
    } else {
      toast.error('Not connected to server. Message not sent.');
    }
  };

  const contextValue: WebSocketContextType = {
    isConnected,
    connectionStatus,
    sendMessage,
    lastMessage,
  };

  return (
    <WebSocketContext.Provider value={contextValue}>
      {children}
    </WebSocketContext.Provider>
  );
};