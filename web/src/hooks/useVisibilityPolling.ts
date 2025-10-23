import { useEffect, useRef } from 'react';

type PollingCallback = () => void | Promise<void>;

interface UseVisibilityPollingOptions {
  intervalMs: number;
  idleMs?: number;
  immediate?: boolean;
}

export const useVisibilityPolling = (
  callback: PollingCallback,
  { intervalMs, idleMs = 5 * 60 * 1000, immediate = true }: UseVisibilityPollingOptions
) => {
  const callbackRef = useRef<PollingCallback>(callback);

  useEffect(() => {
    callbackRef.current = callback;
  }, [callback]);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return;
    }

    let pollTimer: ReturnType<typeof setInterval> | undefined;
    let idleTimer: ReturnType<typeof setTimeout> | undefined;
    let pausedForIdle = false;

    const stopPolling = () => {
      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = undefined;
      }
    };

    const resetIdleTimer = () => {
      if (idleTimer) {
        clearTimeout(idleTimer);
      }
      idleTimer = setTimeout(() => {
        pausedForIdle = true;
        stopPolling();
      }, idleMs);
    };

    const runCallback = () => {
      const fn = callbackRef.current;
      try {
        void fn();
      } catch (error) {
        console.error('Polling callback threw an error:', error);
      }
    };

    const startPolling = (runImmediately: boolean) => {
      if (pollTimer) {
        return;
      }
      pausedForIdle = false;
      resetIdleTimer();
      if (runImmediately) {
        runCallback();
      }
      pollTimer = setInterval(() => {
        if (!document.hidden && !pausedForIdle) {
          runCallback();
        }
      }, intervalMs);
    };

    const handleVisibilityChange = () => {
      if (document.hidden) {
        stopPolling();
      } else {
        resetIdleTimer();
        startPolling(true);
      }
    };

    const handleActivity = () => {
      const shouldRestart = pausedForIdle && !document.hidden;
      pausedForIdle = false;
      resetIdleTimer();
      if (shouldRestart || !pollTimer) {
        startPolling(false);
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('focus', handleActivity);
    window.addEventListener('mousemove', handleActivity);
    window.addEventListener('keydown', handleActivity);
    window.addEventListener('scroll', handleActivity, true);

    startPolling(immediate);

    return () => {
      stopPolling();
      if (idleTimer) {
        clearTimeout(idleTimer);
      }
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('focus', handleActivity);
      window.removeEventListener('mousemove', handleActivity);
      window.removeEventListener('keydown', handleActivity);
      window.removeEventListener('scroll', handleActivity, true);
    };
  }, [intervalMs, idleMs, immediate]);
};
