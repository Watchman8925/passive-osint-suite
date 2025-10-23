export const DEFAULT_TOKEN_TTL_MS = 1000 * 60 * 15; // 15 minutes

type Subscriber = (token: string | null) => void;

let inMemoryToken: string | null = null;
let expiryTimestamp = 0;
let expiryTimer: ReturnType<typeof setTimeout> | undefined;
const subscribers = new Set<Subscriber>();

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
};
