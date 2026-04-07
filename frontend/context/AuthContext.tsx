import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import api from '../services/api';
import { CryptoService } from '../services/CryptoEngine';
import { StorageService } from '../services/StorageService';

interface User {
    username: string;
    email: string;
    id?: string;
}

interface AuthContextType {
    user: User | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    login: (user: User) => void;
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

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [user, setUser] = useState<User | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    const checkAuth = async () => {
        try {
            const response = await api.get('/me');
            if (response.status === 200 && response.data.username) {
                setUser(response.data);

                // Ensure identity keys exist locally (generate if missing)
                let keys = await StorageService.getIdentityKeys();
                if (!keys) {
                    keys = await CryptoService.generateIdentityKeys();
                    await StorageService.saveIdentityKeys(keys);
                }
                // Upload public keys to backend
                api.post('/update_keys', {
                    public_keys: {
                        kyber: keys.kyberPubKey,
                        dilithium: keys.dilithiumPubKey,
                    }
                }).catch(() => {});
            } else {
                setUser(null);
            }
        } catch (error: any) {
            console.log('Auth check failed:', error.response?.status);
            setUser(null);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        checkAuth();
    }, []);

    const login = async (userData: User) => {
        setUser(userData);

        // Generate and persist identity keys on login
        let keys = await StorageService.getIdentityKeys();
        if (!keys) {
            keys = await CryptoService.generateIdentityKeys();
            await StorageService.saveIdentityKeys(keys);
        }
        // Upload public keys to backend
        api.post('/update_keys', {
            public_keys: {
                kyber: keys.kyberPubKey,
                dilithium: keys.dilithiumPubKey,
            }
        }).catch(() => {});
    };

    const logout = async () => {
        try {
            await api.post('/logout');
        } catch (error) {
            console.error('Logout failed', error);
        } finally {
            // Wipe identity keys on logout
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
