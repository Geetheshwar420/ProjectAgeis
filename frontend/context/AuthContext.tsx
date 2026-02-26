import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { User as FirebaseUser } from 'firebase/auth';
import { authService, userService } from '../services/firebaseService';

interface User {
    uid: string;
    username: string;
    email: string;
    displayName?: string;
    photoURL?: string | null;
}

interface AuthContextType {
    user: User | null;
    firebaseUser: FirebaseUser | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    register: (email: string, password: string, displayName: string) => Promise<void>;
    login: (email: string, password: string) => Promise<void>;
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
    const [firebaseUser, setFirebaseUser] = useState<FirebaseUser | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    // Listen to Firebase auth state changes
    useEffect(() => {
        const unsubscribe = authService.onAuthStateChange(async (fbUser) => {
            if (fbUser) {
                try {
                    // Get user profile from Firestore
                    const profile = await userService.getUserProfile(fbUser.uid);
                    if (profile) {
                        setUser({
                            uid: fbUser.uid,
                            email: fbUser.email || '',
                            username: profile.username || fbUser.displayName || 'User',
                            displayName: fbUser.displayName || profile.displayName,
                            photoURL: fbUser.photoURL,
                        });
                    } else {
                        // Fallback if profile not found
                        setUser({
                            uid: fbUser.uid,
                            email: fbUser.email || '',
                            username: fbUser.displayName || 'User',
                            displayName: fbUser.displayName,
                            photoURL: fbUser.photoURL,
                        });
                    }
                    setFirebaseUser(fbUser);
                } catch (error) {
                    console.error('Error loading user profile:', error);
                    setFirebaseUser(fbUser);
                }
            } else {
                setUser(null);
                setFirebaseUser(null);
            }
            setIsLoading(false);
        });

        return () => unsubscribe();
    }, []);

    const register = async (email: string, password: string, displayName: string) => {
        try {
            setIsLoading(true);
            const fbUser = await authService.register(email, password, displayName);
            if (fbUser) {
                setFirebaseUser(fbUser);
                setUser({
                    uid: fbUser.uid,
                    email: fbUser.email || '',
                    username: displayName,
                    displayName: displayName,
                    photoURL: fbUser.photoURL,
                });
            }
        } catch (error) {
            console.error('Registration error:', error);
            throw error;
        } finally {
            setIsLoading(false);
        }
    };

    const login = async (email: string, password: string) => {
        try {
            setIsLoading(true);
            const fbUser = await authService.login(email, password);
            if (fbUser) {
                // Get user profile
                const profile = await userService.getUserProfile(fbUser.uid);
                setFirebaseUser(fbUser);
                setUser({
                    uid: fbUser.uid,
                    email: fbUser.email || '',
                    username: profile?.username || fbUser.displayName || 'User',
                    displayName: fbUser.displayName || profile?.displayName,
                    photoURL: fbUser.photoURL,
                });
            }
        } catch (error) {
            console.error('Login error:', error);
            throw error;
        } finally {
            setIsLoading(false);
        }
    };

    const logout = async () => {
        try {
            setIsLoading(true);
            await authService.logout();
            setUser(null);
            setFirebaseUser(null);
        } catch (error) {
            console.error('Logout error:', error);
            throw error;
        } finally {
            setIsLoading(false);
        }
    };

    const checkAuth = async () => {
        try {
            const fbUser = authService.getCurrentUser();
            if (fbUser) {
                const profile = await userService.getUserProfile(fbUser.uid);
                setUser({
                    uid: fbUser.uid,
                    email: fbUser.email || '',
                    username: profile?.username || fbUser.displayName || 'User',
                    displayName: fbUser.displayName || profile?.displayName,
                    photoURL: fbUser.photoURL,
                });
                setFirebaseUser(fbUser);
            } else {
                setUser(null);
                setFirebaseUser(null);
            }
        } catch (error) {
            console.error('Auth check error:', error);
            setUser(null);
            setFirebaseUser(null);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <AuthContext.Provider value={{
            user,
            firebaseUser,
            isAuthenticated: !!user && !!firebaseUser,
            isLoading,
            register,
            login,
            logout,
            checkAuth
        }}>
            {children}
        </AuthContext.Provider>
    );
};
