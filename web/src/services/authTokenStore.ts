export const DEFAULT_TOKEN_TTL_MS = 1000 * 60 * 15; // 15 minutes

type Subscriber = (token: string | null) => void;

let inMemoryToken: string | null = null;
let expiryTimestamp = 0;
let expiryTimer: ReturnType<typeof setTimeout> | undefined;
const subscribers = new Set<Subscriber>();
const TOKEN_STORAGE_KEY = 'passive-osint-auth-token';
const EXPIRY_STORAGE_KEY = 'passive-osint-auth-expiry';

const getStorage = (): Storage | undefined => {
  if (typeof window === 'undefined' || !window.localStorage) {
    return undefined;
  }
  return window.localStorage;
};

const hydrateFromStorage = () => {
  const storage = getStorage();
  if (!storage) {
    return;
  }

  const storedToken = storage.getItem(TOKEN_STORAGE_KEY);
  const storedExpiry = storage.getItem(EXPIRY_STORAGE_KEY);
  if (!storedToken) {
    return;
  }

  inMemoryToken = storedToken;
  const parsedExpiry = storedExpiry ? Number(storedExpiry) : 0;
  expiryTimestamp = Number.isNaN(parsedExpiry) ? 0 : parsedExpiry;

  if (Number.isFinite(expiryTimestamp) && expiryTimestamp > Date.now()) {
    scheduleExpiry(expiryTimestamp - Date.now());
  } else if (expiryTimestamp && expiryTimestamp !== Number.POSITIVE_INFINITY) {
    clearAuthToken();
  }
};

const notifySubscribers = () => {
  const currentToken = getAuthToken();
  subscribers.forEach((callback) => {
    try {
      callback(currentToken);
    } catch (error) {
      console.error('Auth token subscriber threw an error:', error);
    }
  });
};

const scheduleExpiry = (ttlMs: number) => {
  if (expiryTimer) {
    clearTimeout(expiryTimer);
  }

  expiryTimer = setTimeout(() => {
    clearAuthToken();
  }, ttlMs);
};

export const setAuthToken = (token: string, options?: { ttlMs?: number }) => {
  const ttlMs = options?.ttlMs ?? DEFAULT_TOKEN_TTL_MS;
  inMemoryToken = token;
  const calculatedExpiryTimestamp =
    ttlMs === Number.POSITIVE_INFINITY
      ? Number.POSITIVE_INFINITY
      : Date.now() + ttlMs;
  expiryTimestamp = calculatedExpiryTimestamp;

  if (Number.isFinite(expiryTimestamp)) {
    scheduleExpiry(ttlMs);
  } else if (expiryTimer) {
    clearTimeout(expiryTimer);
    expiryTimer = undefined;
  }

  const storage = getStorage();
  if (storage) {
    storage.setItem(TOKEN_STORAGE_KEY, token);
    storage.setItem(EXPIRY_STORAGE_KEY, String(expiryTimestamp));
  }

  notifySubscribers();
};

export const getAuthToken = (): string | null => {
  if (!inMemoryToken) {
    return null;
  }

  if (Number.isFinite(expiryTimestamp) && Date.now() > expiryTimestamp) {
    clearAuthToken();
    return null;
  }

  return inMemoryToken;
};

export const clearAuthToken = () => {
  inMemoryToken = null;
  expiryTimestamp = 0;
  if (expiryTimer) {
    clearTimeout(expiryTimer);
    expiryTimer = undefined;
  }
  const storage = getStorage();
  if (storage) {
    storage.removeItem(TOKEN_STORAGE_KEY);
    storage.removeItem(EXPIRY_STORAGE_KEY);
  }
  notifySubscribers();
};

export const subscribeToAuthToken = (subscriber: Subscriber) => {
  subscribers.add(subscriber);
  return () => {
    subscribers.delete(subscriber);
  };
};

export const resetAuthTokenStoreForTests = () => {
  subscribers.clear();
  inMemoryToken = null;
  expiryTimestamp = 0;
  if (expiryTimer) {
    clearTimeout(expiryTimer);
    expiryTimer = undefined;
  }
  const storage = getStorage();
  if (storage) {
    storage.removeItem(TOKEN_STORAGE_KEY);
    storage.removeItem(EXPIRY_STORAGE_KEY);
  }
};

hydrateFromStorage();
