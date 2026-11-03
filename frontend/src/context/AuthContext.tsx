/**
 * ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
 * React AuthContext providing authentication state, role-based capabilities, and session lifecycle.
 */
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { UserProfile, UserRole } from '../types';
import apiService from '../services/api';

interface AuthContextType {
  user: UserProfile | null;
  token: string | null;
  role: UserRole | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  canMutate: boolean;
  isAdmin: boolean;
  isOperator: boolean;
  isAuditor: boolean;
  login: (username: string, password: string) => Promise<any>;
  setSession: (token: string, user: UserProfile) => void;
  refreshUser: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(() => {
    try {
      const stored = localStorage.getItem('regubom_user');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  const [token, setToken] = useState<string | null>(() => {
    return localStorage.getItem('regubom_token');
  });

  const [isLoading, setIsLoading] = useState<boolean>(true);

  const refreshUser = async () => {
    try {
      const profile = await apiService.getMe();
      setUser(profile);
      localStorage.setItem('regubom_user', JSON.stringify(profile));
    } catch (err) {
      console.warn('Failed to refresh user profile:', err);
    }
  };

  useEffect(() => {
    const verifySession = async () => {
      const storedToken = localStorage.getItem('regubom_token');
      if (storedToken) {
        try {
          const profile = await apiService.getMe();
          setUser(profile);
          localStorage.setItem('regubom_user', JSON.stringify(profile));
        } catch (err) {
          console.warn('Session verification failed, clearing credentials:', err);
          localStorage.removeItem('regubom_token');
          localStorage.removeItem('regubom_user');
          setToken(null);
          setUser(null);
        }
      }
      setIsLoading(false);
    };

    verifySession();
  }, []);

  const setSession = (newToken: string, newUser: UserProfile) => {
    setToken(newToken);
    setUser(newUser);
    localStorage.setItem('regubom_token', newToken);
    localStorage.setItem('regubom_user', JSON.stringify(newUser));
  };

  const login = async (username: string, password: string): Promise<any> => {
    const data = await apiService.login(username, password);
    if (data.mfa_required) {
      return data;
    }
    if (data.access_token && data.user) {
      setSession(data.access_token, data.user);
    }
    return data;
  };

  const logout = async () => {
    try {
      await apiService.logout();
    } catch {
      // Ignore network errors
    } finally {
      setToken(null);
      setUser(null);
      localStorage.removeItem('regubom_token');
      localStorage.removeItem('regubom_user');
    }
  };

  const role = user?.role || null;
  const isAdmin = role === 'admin';
  const isOperator = role === 'operator';
  const isAuditor = role === 'auditor';
  const canMutate = isAdmin || isOperator;

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        role,
        isAuthenticated: !!token && !!user,
        isLoading,
        canMutate,
        isAdmin,
        isOperator,
        isAuditor,
        login,
        setSession,
        refreshUser,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;
