import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('react-hot-toast', () => ({
  default: {
    success: vi.fn(),
    error: vi.fn(),
    loading: vi.fn(),
  },
}));

vi.mock('../utils/progress', () => ({
  startProgress: vi.fn(),
  finishProgress: vi.fn(),
}));

const loginMock = vi.fn();
const logoutMock = vi.fn();

vi.mock('./api', () => ({
  authApi: {
    login: (...args: unknown[]) => loginMock(...args),
    logout: (...args: unknown[]) => logoutMock(...args),
  },
}));

import osintAPI from './osintAPI';
import { getAuthToken, resetAuthTokenStoreForTests, setAuthToken } from './authTokenStore';

describe('osintAPI authentication', () => {
  beforeEach(() => {
    loginMock.mockReset();
    logoutMock.mockReset();
    resetAuthTokenStoreForTests();
  });

  it('delegates authentication to authApi.login and returns true on success', async () => {
    loginMock.mockResolvedValue({ access_token: 'token-123' });

    const result = await osintAPI.authenticate({ username: 'alice', password: 'secret' });

    expect(loginMock).toHaveBeenCalledWith({ username: 'alice', password: 'secret' });
    expect(result).toBe(true);
  });

  it('returns false when authApi.login throws', async () => {
    loginMock.mockRejectedValue(new Error('invalid credentials'));

    const result = await osintAPI.authenticate({ username: 'alice', password: 'wrong' });

    expect(loginMock).toHaveBeenCalled();
    expect(result).toBe(false);
  });

  it('delegates logout to authApi.logout', async () => {
    logoutMock.mockResolvedValue(undefined);
    setAuthToken('token-123');

    await osintAPI.logout();

    expect(logoutMock).toHaveBeenCalled();
    expect(getAuthToken()).toBeNull();
  });

  it('still clears local storage when logout fails', async () => {
    logoutMock.mockRejectedValue(new Error('network error'));
    setAuthToken('token-123');

    await osintAPI.logout();

    expect(logoutMock).toHaveBeenCalled();
    expect(getAuthToken()).toBeNull();
  });
});
