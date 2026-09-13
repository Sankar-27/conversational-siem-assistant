import React, { createContext, useContext, useState, useEffect } from 'react';
import { User, UserRole } from '../types';
import { authApi } from '../api/client';

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (email: string, pass: string) => Promise<void>;
  register: (name: string, email: string, pass: string, role?: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => {
    const saved = localStorage.getItem('siem_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('siem_access_token'));
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const checkAuth = async () => {
      if (token) {
        try {
          const me = await authApi.getMe();
          setUser(me);
          localStorage.setItem('siem_user', JSON.stringify(me));
        } catch {
          logout();
        }
      }
      setIsLoading(false);
    };
    checkAuth();
  }, [token]);

  const login = async (email: string, pass: string) => {
    const res = await authApi.login(email, pass);
    localStorage.setItem('siem_access_token', res.access_token);
    localStorage.setItem('siem_refresh_token', res.refresh_token);
    const loggedUser: User = {
      id: res.user_id,
      name: res.name,
      email: res.email,
      role: res.role,
    };
    localStorage.setItem('siem_user', JSON.stringify(loggedUser));
    setToken(res.access_token);
    setUser(loggedUser);
  };

  const register = async (name: string, email: string, pass: string, role = 'analyst') => {
    const res = await authApi.register(name, email, pass, role);
    localStorage.setItem('siem_access_token', res.access_token);
    localStorage.setItem('siem_refresh_token', res.refresh_token);
    const registeredUser: User = {
      id: res.user_id,
      name: res.name,
      email: res.email,
      role: res.role,
    };
    localStorage.setItem('siem_user', JSON.stringify(registeredUser));
    setToken(res.access_token);
    setUser(registeredUser);
  };

  const logout = () => {
    localStorage.removeItem('siem_access_token');
    localStorage.removeItem('siem_refresh_token');
    localStorage.removeItem('siem_user');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        login,
        register,
        logout,
        isAuthenticated: !!token,
        isLoading,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
