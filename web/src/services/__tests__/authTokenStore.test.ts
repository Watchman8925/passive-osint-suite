import { describe, expect, it, vi, afterEach } from 'vitest';

const TOKEN_KEY = 'passive-osint-auth-token';
const EXPIRY_KEY = 'passive-osint-auth-expiry';

const createStorage = () => {
  const store = new Map<string, string>();
  return {
    store,
    window: {
      localStorage: {
        getItem: (key: string) => (store.has(key) ? store.get(key)! : null),
        setItem: (key: string, value: string) => {
          store.set(key, value);
        },
        removeItem: (key: string) => {
          store.delete(key);
        },
        clear: () => store.clear(),
      },
    } as unknown as Window,
  };
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe('authTokenStore persistence', () => {
  it('persists token data across reloads', async () => {
    const sharedStorage = createStorage();
    vi.stubGlobal('window', sharedStorage.window);
    const firstModule = await import('../authTokenStore');
    firstModule.setAuthToken('test-token', { ttlMs: Number.POSITIVE_INFINITY });

    expect(sharedStorage.store.get(TOKEN_KEY)).toBe('test-token');
    expect(sharedStorage.store.get(EXPIRY_KEY)).toBe('Infinity');

    vi.resetModules();
    vi.unstubAllGlobals();
    vi.stubGlobal('window', sharedStorage.window);
    const reloadedModule = await import('../authTokenStore');

    expect(reloadedModule.getAuthToken()).toBe('test-token');
    reloadedModule.clearAuthToken();
  });

  it('clears persisted values when clearAuthToken is called', async () => {
    const storageInstance = createStorage();
    vi.stubGlobal('window', storageInstance.window);
    const module = await import('../authTokenStore');
    module.setAuthToken('token', { ttlMs: 1000 });
    expect(storageInstance.store.get(TOKEN_KEY)).toBe('token');

    module.clearAuthToken();
    expect(storageInstance.store.has(TOKEN_KEY)).toBe(false);
    expect(storageInstance.store.has(EXPIRY_KEY)).toBe(false);
  });
});

