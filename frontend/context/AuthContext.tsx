import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import api from '../services/api';
import { CryptoService } from '../services/CryptoEngine';
import { StorageService } from '../services/StorageService';

interface User {
    username: string;
    email?: string;
    id?: string;
}

interface AuthContextType {
    user: User | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    login: (username: string, password: string) => Promise<void>;
    logout: () => Promise<void>;
    checkAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

async function ensureAndUploadKeys() {
    let keys = await StorageService.getIdentityKeys();
    if (!keys) {
        keys = await CryptoService.generateIdentityKeys();
        await StorageService.saveIdentityKeys(keys);
    }
    api.post('/update_keys', {
        public_keys: {
            kyber: keys.kyberPubKey,
            dilithium: keys.dilithiumPubKey,
        }
    }).catch(() => {});
}

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [user, setUser] = useState<User | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    const checkAuth = async () => {
        try {
            const response = await api.get('/me');
            if (response.status === 200 && response.data.username) {
                setUser(response.data);
                ensureAndUploadKeys();
            } else {
                setUser(null);
            }
        } catch {
            setUser(null);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        checkAuth();
    }, []);

    const login = async (username: string, password: string) => {
        const response = await api.post('/login', { username, password });
        if (response.status === 200 && response.data.user) {
            setUser(response.data.user);
            ensureAndUploadKeys();
        } else {
            throw new Error(response.data?.error || 'Login failed');
        }
    };

    const logout = async () => {
        try {
            await api.post('/logout');
        } catch { /* ignore */ } finally {
            await StorageService.clearIdentityKeys();
            setUser(null);
        }
    };

    return (
        <AuthContext.Provider value={{
            user,
            isAuthenticated: !!user,
            isLoading,
            login,
            logout,
            checkAuth
        }}>
            {children}
        </AuthContext.Provider>
    );
};
