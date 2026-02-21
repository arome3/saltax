"use client";

import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  useCallback,
  type ReactNode,
} from "react";
import React from "react";
import type { LogEvent } from "@/types";

interface WebSocketContextValue {
  events: LogEvent[];
  connected: boolean;
  paused: boolean;
  setPaused: (paused: boolean) => void;
  clearEvents: () => void;
}

const WebSocketContext = createContext<WebSocketContextValue>({
  events: [],
  connected: false,
  paused: false,
  setPaused: () => {},
  clearEvents: () => {},
});

const MAX_EVENTS = 10_000;
const RECONNECT_MAX_DELAY = 30_000;

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const [events, setEvents] = useState<LogEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const retryCount = useRef(0);
  const pausedRef = useRef(false);

  // Keep pausedRef in sync
  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  const clearEvents = useCallback(() => setEvents([]), []);

  useEffect(() => {
    let mounted = true;
    let timeoutId: ReturnType<typeof setTimeout>;

    function connect() {
      if (!mounted) return;

      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(`${protocol}//${window.location.host}/ws/logs`);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mounted) return;
        setConnected(true);
        retryCount.current = 0;
      };

      ws.onmessage = (event) => {
        if (!mounted || pausedRef.current) return;
        try {
          const data = JSON.parse(event.data) as LogEvent;
          setEvents((prev) => {
            const next = [data, ...prev];
            return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next;
          });
        } catch {
          // Ignore malformed messages
        }
      };

      ws.onclose = () => {
        if (!mounted) return;
        setConnected(false);
        // Exponential backoff reconnection
        const delay = Math.min(
          1000 * Math.pow(2, retryCount.current),
          RECONNECT_MAX_DELAY,
        );
        retryCount.current++;
        timeoutId = setTimeout(connect, delay);
      };

      ws.onerror = () => {
        ws.close();
      };
    }

    connect();

    return () => {
      mounted = false;
      clearTimeout(timeoutId);
      wsRef.current?.close();
    };
  }, []);

  return React.createElement(
    WebSocketContext.Provider,
    { value: { events, connected, paused, setPaused, clearEvents } },
    children,
  );
}

export function useWebSocket() {
  return useContext(WebSocketContext);
}
