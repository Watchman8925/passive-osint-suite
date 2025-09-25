import { useEffect, useRef, useState, useCallback } from 'react';
import toast from 'react-hot-toast';
import { WebSocketMessage } from '../types/investigation';
import type { PlannedTask } from '../types/autonomy';

interface UseWebSocketOptions {
  onMessage?: (message: string) => void;
  onOpen?: () => void;
  onClose?: () => void;
  onError?: (error: Event) => void;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

interface UseWebSocketReturn {
  isConnected: boolean;
  lastMessage: string | null;
  sendMessage: (message: string | object) => void;
  disconnect: () => void;
  reconnect: () => void;
  connectionStatus: 'connecting' | 'connected' | 'disconnected' | 'error';
}

export function useWebSocket(
  url: string,
  options: UseWebSocketOptions = {}
): UseWebSocketReturn {
  const {
    onMessage,
    onOpen,
    onClose,
    onError,
    reconnectInterval = 3000,
    maxReconnectAttempts = 5
  } = options;

  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected' | 'error'>('disconnected');
  
  const ws = useRef<WebSocket | null>(null);
  const reconnectAttempts = useRef(0);
  const reconnectTimer = useRef<NodeJS.Timeout | null>(null);
  const shouldReconnect = useRef(true);

  const getWebSocketUrl = useCallback(() => {
    const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    const wsUrl = baseUrl.replace('http', 'ws');
    return `${wsUrl}${url}`;
  }, [url]);

  const connect = useCallback(() => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      return;
    }

    setConnectionStatus('connecting');
    
    try {
      const wsUrl = getWebSocketUrl();
      ws.current = new WebSocket(wsUrl);

      ws.current.onopen = () => {
        setIsConnected(true);
        setConnectionStatus('connected');
        reconnectAttempts.current = 0;
        onOpen?.();
      };

      ws.current.onmessage = (event) => {
        const message = event.data;
        setLastMessage(message);
        onMessage?.(message);
      };

      ws.current.onclose = () => {
        setIsConnected(false);
        setConnectionStatus('disconnected');
        onClose?.();

        // Attempt to reconnect if enabled and within limits
        if (shouldReconnect.current && reconnectAttempts.current < maxReconnectAttempts) {
          reconnectAttempts.current++;
          reconnectTimer.current = setTimeout(() => {
            connect();
          }, reconnectInterval);
        }
      };

      ws.current.onerror = (error) => {
        setConnectionStatus('error');
        onError?.(error);
      };

    } catch (error) {
      setConnectionStatus('error');
      console.error('WebSocket connection error:', error);
    }
  }, [getWebSocketUrl, onOpen, onMessage, onClose, onError, reconnectInterval, maxReconnectAttempts]);

  const disconnect = useCallback(() => {
    shouldReconnect.current = false;
    
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current);
      reconnectTimer.current = null;
    }

    if (ws.current) {
      ws.current.close();
      ws.current = null;
    }
    
    setIsConnected(false);
    setConnectionStatus('disconnected');
  }, []);

  const reconnect = useCallback(() => {
    disconnect();
    shouldReconnect.current = true;
    reconnectAttempts.current = 0;
    setTimeout(connect, 100);
  }, [connect, disconnect]);

  const sendMessage = useCallback((message: string | object) => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      const messageString = typeof message === 'string' ? message : JSON.stringify(message);
      ws.current.send(messageString);
    } else {
      console.warn('WebSocket is not connected. Message not sent:', message);
    }
  }, []);

  // Initial connection
  useEffect(() => {
    connect();

    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      shouldReconnect.current = false;
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current);
      }
      if (ws.current) {
        ws.current.close();
      }
    };
  }, []);

  return {
    isConnected,
    lastMessage,
    sendMessage,
    disconnect,
    reconnect,
    connectionStatus
  };
}

// Specialized hook for investigation updates
export function useInvestigationWebSocket() {
  const [investigationUpdates, setInvestigationUpdates] = useState<WebSocketMessage[]>([]);
  const [taskUpdates, setTaskUpdates] = useState<WebSocketMessage[]>([]);
  const [planTasks, setPlanTasks] = useState<Record<string, PlannedTask>>({});

  const { isConnected, lastMessage, sendMessage, connectionStatus } = useWebSocket('/api/ws', {
    onMessage: (message: string) => {
      try {
        const data: WebSocketMessage = JSON.parse(message);
        if (data.type === 'investigation_update') {
          setInvestigationUpdates(prev => [...prev, data]);
          // Execution engine events come through as investigation_update with event field
          const evt = (data as any).data?.event || (data as any).event;
          if (evt && (evt.startsWith('task_') || evt.startsWith('task'))) {
            const capId = (data as any).data?.capability_id || (data as any).capability_id;
            const taskId = (data as any).data?.task_id || (data as any).task_id;
            const status = (data as any).data?.status || (data as any).status;
            if (taskId && capId && status) {
              setPlanTasks(prev => ({
                ...prev,
                [taskId]: {
                  id: taskId,
                  capability_id: capId,
                  inputs: {},
                  depends_on: [],
                  status,
                }
              }));
              if (status === 'failed') {
                toast.error(`Task ${taskId} failed`);
              } else if (status === 'completed') {
                toast.success(`Task ${taskId} completed`, { duration: 2000 });
              }
            }
          }
        } else if (data.type === 'task_update') {
          setTaskUpdates(prev => [...prev, data]);
        }
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error);
      }
    }
  });

  const subscribeToInvestigation = useCallback((investigationId: string) => {
    sendMessage({
      type: 'subscribe',
      investigation_id: investigationId
    });
  }, [sendMessage]);

  const unsubscribeFromInvestigation = useCallback((investigationId: string) => {
    sendMessage({
      type: 'unsubscribe',
      investigation_id: investigationId
    });
  }, [sendMessage]);

  const clearUpdates = useCallback(() => {
    setInvestigationUpdates([]);
    setTaskUpdates([]);
  }, []);

  return {
    isConnected,
    connectionStatus,
    investigationUpdates,
    taskUpdates,
    planTasks,
    subscribeToInvestigation,
    unsubscribeFromInvestigation,
    clearUpdates,
    lastMessage
  };
}