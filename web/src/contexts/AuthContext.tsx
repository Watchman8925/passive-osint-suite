import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import {
  clearAuthToken,
  getAuthToken,
  setAuthToken,
  subscribeToAuthToken,
} from '../services/authTokenStore';

interface AuthContextValue {
  token: string | null;
  user: any | null;
  isAuthenticated: boolean;
  setSession: (user: any, token: string, options?: { ttlMs?: number }) => void;
  clearSession: () => void;
  updateUser: (user: any | null) => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(() => getAuthToken());
  const [user, setUser] = useState<any | null>(null);

  useEffect(() => {
    const unsubscribe = subscribeToAuthToken((nextToken) => {
      setToken(nextToken);
      if (!nextToken) {
        setUser(null);
      }
    });
    return unsubscribe;
  }, []);

  const setSession = useCallback(
    (userData: any, nextToken: string, options?: { ttlMs?: number }) => {
      setAuthToken(nextToken, options);
      setUser(userData);
    },
    []
  );

  const clearSession = useCallback(() => {
    clearAuthToken();
    setUser(null);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      token,
      user,
      isAuthenticated: Boolean(token),
      setSession,
      clearSession,
      updateUser: setUser,
    }),
    [token, user, setSession, clearSession]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
