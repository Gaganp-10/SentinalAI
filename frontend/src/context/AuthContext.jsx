import React, { createContext, useState, useEffect, useContext } from 'react';
import { getMe, login as apiLogin } from '../api/auth';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);

  // Startup hook to load user if JWT exists
  useEffect(() => {
    const initializeAuth = async () => {
      const storedToken = localStorage.getItem('sast_token');
      if (storedToken) {
        setToken(storedToken);
        try {
          const userData = await getMe();
          setUser(userData);
        } catch (error) {
          console.error("Auth initialization failed:", error);
          localStorage.removeItem('sast_token');
          setToken(null);
          setUser(null);
        }
      }
      setLoading(false);
    };
    initializeAuth();
  }, []);

  const login = async (username, password) => {
    setLoading(true);
    try {
      const data = await apiLogin(username, password);
      localStorage.setItem('sast_token', data.access_token);
      setToken(data.access_token);
      
      // Fetch user profile immediately
      const userData = await getMe();
      setUser(userData);
      return userData;
    } catch (error) {
      localStorage.removeItem('sast_token');
      setToken(null);
      setUser(null);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('sast_token');
    setToken(null);
    setUser(null);
    window.location.href = '/login';
  };

  const value = {
    user,
    token,
    loading,
    isAuthenticated: !!user,
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
