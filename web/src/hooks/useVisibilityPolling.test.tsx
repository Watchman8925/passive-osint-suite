import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useVisibilityPolling } from './useVisibilityPolling';

const setDocumentHidden = (hidden: boolean) => {
  Object.defineProperty(document, 'hidden', {
    configurable: true,
    get: () => hidden,
  });
};

describe('useVisibilityPolling', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    setDocumentHidden(false);
  });

  afterEach(() => {
    vi.useRealTimers();
    setDocumentHidden(false);
  });

  it('invokes the callback immediately and on interval while visible', () => {
    const callback = vi.fn();
    renderHook(() => useVisibilityPolling(callback, { intervalMs: 1000, idleMs: 5000 }));

    expect(callback).toHaveBeenCalledTimes(1);

    act(() => {
      vi.advanceTimersByTime(3000);
    });

    expect(callback).toHaveBeenCalledTimes(4);
  });

  it('pauses polling when the document becomes hidden and resumes when visible', () => {
    const callback = vi.fn();
    renderHook(() => useVisibilityPolling(callback, { intervalMs: 1000, idleMs: 5000 }));

    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(callback).toHaveBeenCalledTimes(2);

    act(() => {
      setDocumentHidden(true);
      document.dispatchEvent(new Event('visibilitychange'));
      vi.advanceTimersByTime(5000);
    });

    expect(callback).toHaveBeenCalledTimes(2);

    act(() => {
      setDocumentHidden(false);
      document.dispatchEvent(new Event('visibilitychange'));
      vi.advanceTimersByTime(1000);
    });

    expect(callback).toHaveBeenCalledTimes(4);
  });
});
