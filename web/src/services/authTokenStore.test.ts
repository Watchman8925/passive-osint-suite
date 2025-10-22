import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  clearAuthToken,
  getAuthToken,
  resetAuthTokenStoreForTests,
  setAuthToken,
  subscribeToAuthToken,
} from './authTokenStore';

describe('authTokenStore', () => {
  beforeEach(() => {
    resetAuthTokenStoreForTests();
    vi.useRealTimers();
  });

  it('stores and retrieves a token', () => {
    expect(getAuthToken()).toBeNull();
    setAuthToken('token-abc');
    expect(getAuthToken()).toBe('token-abc');
  });

  it('clears the token on demand', () => {
    setAuthToken('token-abc');
    clearAuthToken();
    expect(getAuthToken()).toBeNull();
  });

  it('expires the token after the configured ttl', () => {
    vi.useFakeTimers();
    setAuthToken('token-abc', { ttlMs: 1000 });
    expect(getAuthToken()).toBe('token-abc');

    vi.advanceTimersByTime(1001);
    expect(getAuthToken()).toBeNull();
  });

  it('notifies subscribers when the token changes', () => {
    const listener = vi.fn();
    const unsubscribe = subscribeToAuthToken(listener);

    setAuthToken('token-abc');
    clearAuthToken();

    expect(listener).toHaveBeenCalledTimes(2);
    unsubscribe();
  });
});
