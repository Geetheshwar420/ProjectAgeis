import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import io, { Socket } from 'socket.io-client';
import { getApiBaseUrl } from '../services/api';

interface SocketContextType {
    socket: Socket | null;
    onlineUsers: Set<string>;
    isConnected: boolean;
}

const SocketContext = createContext<SocketContextType | undefined>(undefined);

export const useSocket = () => {
    const context = useContext(SocketContext);
    if (!context) {
        throw new Error('useSocket must be used within a SocketProvider');
    }
    return context;
};

interface SocketProviderProps {
    children: ReactNode;
    currentUser: any; // Replace with proper User type
}

export const SocketProvider: React.FC<SocketProviderProps> = ({ children, currentUser }) => {
    const [socket, setSocket] = useState<Socket | null>(null);
    const [onlineUsers, setOnlineUsers] = useState<Set<string>>(new Set());
    const [isConnected, setIsConnected] = useState(false);

    useEffect(() => {
        if (!currentUser) {
            if (socket) {
                socket.disconnect();
                setSocket(null);
                setIsConnected(false);
            }
            return;
        }

        // Only create a new socket if we don't have one or if the user changed
        if (socket && socket.connected) {
            console.log('Socket already connected, skipping reconnection');
            return;
        }

        const socketUrl = getApiBaseUrl();
        console.log('Creating new socket connection to:', socketUrl);
        const newSocket = io(socketUrl, {
            withCredentials: true,
            transports: ['websocket', 'polling'],
        });

        newSocket.on('connect', () => {
            console.log('Socket connected');
            setIsConnected(true);
        });

        newSocket.on('disconnect', () => {
            console.log('Socket disconnected');
            setIsConnected(false);
        });

        newSocket.on('online_users_list', (data: { users: string[] }) => {
            setOnlineUsers(new Set(data.users));
        });

        newSocket.on('user_status_changed', (data: { username: string; is_online: boolean }) => {
            setOnlineUsers(prev => {
                const newSet = new Set(prev);
                if (data.is_online) {
                    newSet.add(data.username);
                } else {
                    newSet.delete(data.username);
                }
                return newSet;
            });
        });

        setSocket(newSocket);

        return () => {
            console.log('Cleaning up socket connection');
            newSocket.disconnect();
        };
    }, [currentUser?.username]); // Only reconnect if username changes

    return (
        <SocketContext.Provider value={{ socket, onlineUsers, isConnected }}>
            {children}
        </SocketContext.Provider>
    );
};
