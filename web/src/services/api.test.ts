import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import apiClient, { AUTH_TOKEN_KEY, authApi } from './api';

describe('authApi', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('stores the access token returned from /auth/login', async () => {
    const credentials = { username: 'alice', password: 'secret' };
    const postMock = vi
      .spyOn(apiClient.client, 'post')
      .mockResolvedValue({ data: { access_token: 'token-123' } });

    const response = await authApi.login(credentials);

    expect(postMock).toHaveBeenCalledWith('/auth/login', credentials);
    expect(response).toEqual({ access_token: 'token-123' });
    expect(localStorage.getItem(AUTH_TOKEN_KEY)).toBe('token-123');
  });

  it('clears the stored token when logout succeeds', async () => {
    localStorage.setItem(AUTH_TOKEN_KEY, 'token-123');
    const postMock = vi
      .spyOn(apiClient.client, 'post')
      .mockResolvedValue({ data: {} });

    await authApi.logout();

    expect(postMock).toHaveBeenCalledWith('/auth/logout');
    expect(localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();
  });

  it('clears the stored token even when logout fails', async () => {
    localStorage.setItem(AUTH_TOKEN_KEY, 'token-123');
    const postMock = vi
      .spyOn(apiClient.client, 'post')
      .mockRejectedValue(new Error('network failure'));

    await expect(authApi.logout()).rejects.toThrow('network failure');

    expect(postMock).toHaveBeenCalledWith('/auth/logout');
    expect(localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();
  });
});
