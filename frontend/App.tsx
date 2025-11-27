import React, { useState, useEffect } from 'react';
import LeftSidebar from './components/LeftSidebar';
import ChatWindow from './components/ChatWindow';
import RightSidebar from './components/RightSidebar';
import QRCodeModal from './components/QRCodeModal';
import LandingPage from './components/LandingPage';
import LoginPage from './components/LoginPage';
import SignupPage from './components/SignupPage';
import { AddFriendModal, InviteModal } from './components/Modals';
import { Chat, MessageType, MessageStatus, TabType } from './types';
import { AuthProvider, useAuth } from './context/AuthContext';
import { SocketProvider, useSocket } from './context/SocketContext';
import api from './services/api';

type AppView = 'landing' | 'login' | 'signup' | 'app';

const AppContent: React.FC = () => {
  const { user, isAuthenticated, logout, isLoading } = useAuth();
  const { socket } = useSocket();

  // Initialize theme from system preference or localStorage
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    // Check localStorage first
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'light' || savedTheme === 'dark') {
      return savedTheme;
    }
    // Fall back to system preference
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  });

  const [view, setView] = useState<AppView>('landing');

  // App State
  const [activeChatId, setActiveChatId] = useState<string | null>(null);
  const [isRightSidebarOpen, setIsRightSidebarOpen] = useState(true);
  const [isQRModalOpen, setIsQRModalOpen] = useState(false);
  const [isAddFriendModalOpen, setIsAddFriendModalOpen] = useState(false);
  const [isInviteModalOpen, setIsInviteModalOpen] = useState(false);
  const [chats, setChats] = useState<Chat[]>([]);
  const [activeTab, setActiveTab] = useState<TabType>('messages');

  // Apply theme to document and save to localStorage
  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('theme', theme);
  }, [theme]);

  // Fetch users/chats on load
  useEffect(() => {
    const fetchChats = async () => {
      if (!user) return;
      try {
        const response = await api.get('/users');
        const users = response.data.filter((u: any) => u.username !== user.username);

        // Map users to Chat objects
        const mappedChats: Chat[] = users.map((u: any) => ({
          id: u.username,
          participants: [{
            id: u.username,
            name: u.username,
            avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=' + u.username,
            status: u.is_online ? 'online' : 'offline',
            lastSeen: 'recently'
          }],
          messages: [],
          unreadCount: 0,
          isPinned: false,
          type: 'direct'
        }));
        setChats(mappedChats);
      } catch (error) {
        console.error('Failed to fetch chats', error);
      }
    };
    fetchChats();
  }, [user]);

  // Socket listeners
  useEffect(() => {
    if (!socket) return;

    socket.on('new_message', (message: any) => {
      setChats(prevChats => prevChats.map(chat => {
        const otherId = message.sender_id === user?.username ? message.recipient_id : message.sender_id;
        if (chat.id === otherId) {
          const newMsg = {
            id: message._id || `m_${Date.now()}`,
            senderId: message.sender_id,
            content: message.encrypted_message, // Note: This is encrypted! ChatWindow needs to decrypt.
            // For now, we assume ChatWindow handles decryption or we store it as is.
            // Actually, if we receive it here, we might want to decrypt it if we have the session key.
            // But for MVP, let's pass it through.
            type: MessageType.TEXT,
            timestamp: new Date(message.timestamp),
            status: MessageStatus.DELIVERED,
          };
          return {
            ...chat,
            messages: [...chat.messages, newMsg],
            unreadCount: message.sender_id !== user?.username ? chat.unreadCount + 1 : chat.unreadCount
          };
        }
        return chat;
      }));
    });

    return () => {
      socket.off('new_message');
    };
  }, [socket, user]);

  useEffect(() => {
    if (isAuthenticated) {
      setView('app');
    } else if (view === 'app') {
      setView('landing');
    }
  }, [isAuthenticated]);

  useEffect(() => {
    // Check system preference
    if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
      setTheme('dark');
    }
  }, []);

  useEffect(() => {
    const html = document.documentElement;
    if (theme === 'dark') {
      html.classList.add('dark');
    } else {
      html.classList.remove('dark');
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === 'light' ? 'dark' : 'light');
  };

  const handleLogout = async () => {
    await logout();
    setView('landing');
    setActiveChatId(null);
  };

  const handleAddFriend = async (username: string) => {
    try {
      await api.post('/friend-request', { recipient: username });
      alert(`Friend request sent to ${username}!`);
      setIsAddFriendModalOpen(false);
    } catch (error: any) {
      alert(error.response?.data?.error || 'Failed to send friend request');
    }
  };

  const activeChat = activeChatId ? chats.find(c => c.id === activeChatId) || null : null;

  const handleSendMessage = (text: string, type: MessageType = MessageType.TEXT) => {
    if (!activeChatId || !user) return;

    // Optimistic update
    const newMessage = {
      id: `m_${Date.now()}`,
      senderId: user.username, // Use username as ID
      content: text,
      type: type,
      timestamp: new Date(),
      status: MessageStatus.SENDING,
    };

    setChats(prevChats => prevChats.map(chat => {
      if (chat.id === activeChatId) {
        return {
          ...chat,
          messages: [...chat.messages, newMessage]
        };
      }
      return chat;
    }));
  };

  if (isLoading) {
    return <div className="flex h-screen items-center justify-center bg-[#0f172a] text-white">Loading...</div>;
  }

  if (view === 'landing') {
    return <LandingPage onNavigate={(page) => setView(page)} theme={theme} setTheme={setTheme} />;
  }

  if (view === 'login') {
    return (
      <LoginPage
        onLogin={() => setView('app')}
        onNavigateSignup={() => setView('signup')}
        onNavigateHome={() => setView('landing')}
      />
    );
  }

  if (view === 'signup') {
    return (
      <SignupPage
        onLogin={() => setView('app')}
        onNavigateLogin={() => setView('login')}
        onNavigateHome={() => setView('landing')}
      />
    );
  }

  // --- Main App View ---

  return (
    <div className="flex h-screen w-screen bg-gray-100 dark:bg-slate-900 overflow-hidden font-sans text-slate-900 dark:text-slate-100 selection:bg-teal-500 selection:text-white">
      {/* Background Ambience */}
      <div className="fixed inset-0 z-0 pointer-events-none">
        <div className="absolute -top-[20%] -left-[10%] w-[50%] h-[50%] rounded-full bg-teal-500/10 blur-[100px]" />
        <div className="absolute -bottom-[20%] -right-[10%] w-[50%] h-[50%] rounded-full bg-purple-500/10 blur-[100px]" />
      </div>

      <div className="flex-1 flex z-10 relative shadow-2xl overflow-hidden md:m-4 md:rounded-2xl md:border md:border-white/20 dark:md:border-gray-700 bg-white/40 dark:bg-black/40 backdrop-blur-3xl animate-scale-in">

        {/* Left Sidebar - Slides out on mobile when chat is active */}
        <div className={`w-full md:w-[340px] flex-shrink-0 h-full transition-transform duration-300 ease-in-out md:translate-x-0 ${activeChatId ? '-translate-x-full md:translate-x-0 absolute md:relative' : 'translate-x-0'} z-10`}>
          <LeftSidebar
            chats={chats}
            activeChatId={activeChatId}
            onSelectChat={setActiveChatId}
            activeTab={activeTab}
            setActiveTab={setActiveTab}
            onOpenQR={() => setIsQRModalOpen(true)}
            onAddFriend={() => setIsAddFriendModalOpen(true)}
            onInvite={() => setIsInviteModalOpen(true)}
            onLogout={handleLogout}
            theme={theme}
            setTheme={setTheme}
          />
        </div>

        {/* Center Panel - Slides in from right on mobile when chat is selected */}
        <div className={`flex-1 flex flex-col relative min-w-0 transition-transform duration-300 ease-in-out ${activeChatId ? 'translate-x-0' : 'translate-x-full md:translate-x-0'} ${activeChatId ? 'absolute md:relative inset-0 z-20' : 'md:relative'}`}>
          <ChatWindow
            chat={activeChat}
            onSendMessage={handleSendMessage}
            onToggleRightSidebar={() => setIsRightSidebarOpen(!isRightSidebarOpen)}
            onBack={() => setActiveChatId(null)}
          />
        </div>

        {/* Right Sidebar */}
        <div className={`hidden lg:block transition-all duration-300 ease-in-out relative ${isRightSidebarOpen ? 'w-[360px]' : 'w-0'} overflow-hidden`}>
          <RightSidebar
            chat={activeChat}
            isOpen={isRightSidebarOpen}
            onClose={() => setIsRightSidebarOpen(false)}
          />
        </div>

      </div>

      {/* Modals */}
      <QRCodeModal
        isOpen={isQRModalOpen}
        onClose={() => setIsQRModalOpen(false)}
        currentUser={user || { id: 'guest', name: 'Guest', avatar: '' }}
      />
      <AddFriendModal
        isOpen={isAddFriendModalOpen}
        onClose={() => setIsAddFriendModalOpen(false)}
        onAdd={handleAddFriend}
      />
      <InviteModal
        isOpen={isInviteModalOpen}
        onClose={() => setIsInviteModalOpen(false)}
        currentUser={user || { id: 'guest', name: 'Guest', avatar: '' }}
      />
    </div>
  );
};


const App: React.FC = () => {
  return (
    <AuthProvider>
      <SocketWrapper />
    </AuthProvider>
  );
};

// Separate wrapper to access AuthContext
const SocketWrapper: React.FC = () => {
  const { user } = useAuth();
  return (
    <SocketProvider currentUser={user}>
      <AppContent />
    </SocketProvider>
  );
};

export default App;
