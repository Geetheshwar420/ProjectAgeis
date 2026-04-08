import React, { useState, useEffect, useCallback, useRef } from 'react';
import LeftSidebar from './components/LeftSidebar';
import ChatWindow from './components/ChatWindow';
import RightSidebar from './components/RightSidebar';
import QRCodeModal from './components/QRCodeModal';
import LandingPage from './components/LandingPage';
import LoginPage from './components/LoginPage';
import SignupPage from './components/SignupPage';
import ErrorBoundary from './components/ErrorBoundary';
import { AddFriendModal, InviteModal, ProfileModal, SettingsModal } from './components/Modals';
import { Chat, MessageType, MessageStatus, TabType } from './types';
import { AuthProvider, useAuth } from './context/AuthContext';
import { SocketProvider, useSocket } from './context/SocketContext';
import api from './services/api';
import { CryptoService } from './services/CryptoEngine';
import { StorageService } from './services/StorageService';

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

  const [view, setView] = useState<AppView>(() => {
    // Detect mobile for default landing
    if (typeof window !== 'undefined' && window.innerWidth < 768) {
      return 'login';
    }
    return 'landing';
  });

  // App State
  const [activeChatId, setActiveChatId] = useState<string | null>(null);
  const [isRightSidebarOpen, setIsRightSidebarOpen] = useState(true);
  const [isQRModalOpen, setIsQRModalOpen] = useState(false);
  const [isAddFriendModalOpen, setIsAddFriendModalOpen] = useState(false);
  const [isInviteModalOpen, setIsInviteModalOpen] = useState(false);
  const [isProfileModalOpen, setIsProfileModalOpen] = useState(false);
  const [isSettingsModalOpen, setIsSettingsModalOpen] = useState(false);
  const [chats, setChats] = useState<Chat[]>([]);
  const chatsRef = useRef<Chat[]>([]);

  useEffect(() => {
    chatsRef.current = chats;
  }, [chats]);

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
        console.log('[DEBUG] App: Fetching friends for chat list...');
        const response = await api.get('/friends');
        const users = response.data;
        console.log('[DEBUG] App: Fetched users:', users);

        // Map users to Chat objects and LOAD HISTORY
        const mappedChats: Chat[] = await Promise.all(users.map(async (u: any) => {
          const chatHistory = await StorageService.getMessages(u.username);
          const sharedKey = await CryptoService.getSharedKeyForPeer(user.username, u.username);

          // Decrypt history messages if needed
          const decryptedMessages = await Promise.all(chatHistory.map(async (msg) => {
            let content = msg.content;
            if (msg.is_encrypted) {
              content = await CryptoService.decryptMessageSafe(msg.content, sharedKey);
            }
            return {
              id: msg.id,
              senderId: msg.sender_id,
              content: content,
              type: (msg.type as MessageType) || MessageType.TEXT,
              timestamp: new Date(msg.timestamp),
              status: MessageStatus.READ,
              mediaUrl: msg.url,
              fileName: msg.type === 'file' ? msg.content : undefined,
            };
          }));

          return {
            id: u.username,
            participants: [{
              id: u.username,
              name: u.username,
              username: u.username,
              avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=' + u.username,
              status: u.is_online ? 'online' : 'offline',
              lastSeen: 'recently',
              public_keys: u.public_keys
            }],
            messages: decryptedMessages,
            unreadCount: 0,
            isPinned: false,
            type: 'direct' as const
          };
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

    socket.on('new_message', async (message: any) => {
      // 1. Decrypt if needed
      let decryptedContent = message.encrypted_message || message.content || '';

      if (user && message.sender_id !== user.username) {
        try {
          if (message.is_hybrid) {
            // HYBRID FLOW
            let myKeys = await StorageService.getIdentityKeys();

            // Generate keys on-the-fly if missing
            if (!myKeys) {
              const newKeys = await CryptoService.generateIdentityKeys();
              await StorageService.saveIdentityKeys(newKeys);
              myKeys = newKeys;
              // Upload to backend
              api.post('/update_keys', {
                public_keys: { kyber: newKeys.kyberPubKey, dilithium: newKeys.dilithiumPubKey }
              }).catch(() => {});
            }

            let senderPubKey: string | undefined;

            // Try local cache first
            const senderChat = chatsRef.current.find(c => c.id === message.sender_id);
            senderPubKey = senderChat?.participants[0]?.public_keys?.dilithium;

            // Fetch from server if missing
            if (!senderPubKey) {
              try {
                const resp = await api.get(`/user/${message.sender_id}`);
                senderPubKey = resp.data.public_keys?.dilithium;
              } catch (e) {
                console.error("Failed to fetch sender public keys:", e);
              }
            }

            if (myKeys && senderPubKey) {
              try {
                decryptedContent = await CryptoService.hybridDecrypt(
                  message.encrypted_message,
                  myKeys.kyberSecKey,
                  senderPubKey,
                  user.username,
                  message.sender_id
                );
              } catch (decryptErr) {
                console.error('hybridDecrypt failed:', decryptErr);
                decryptedContent = '[Encrypted message - decryption failed]';
              }
            } else {
              decryptedContent = '[Encrypted message - keys unavailable]';
            }
          } else if (message.encrypted_message) {
            // DETERMINISTIC FALLBACK: AES-GCM encrypted with shared key
            const sharedKey = await CryptoService.getSharedKeyForPeer(user.username, message.sender_id);
            try {
              decryptedContent = await CryptoService.decryptMessage(message.encrypted_message, sharedKey);
            } catch {
              decryptedContent = message.encrypted_message;
            }
          }
        } catch (err) {
          console.error('Decryption failed for incoming message:', err);
          decryptedContent = '[Encrypted message - error]';
        }
      }

      setChats(prevChats => prevChats.map(chat => {
        const otherId = message.sender_id === user?.username ? message.recipient_id : message.sender_id;
        if (chat.id === otherId) {
          const newMsg = {
            id: message._id || `m_${Date.now()}`,
            senderId: message.sender_id,
            content: decryptedContent,
            type: message.type || MessageType.TEXT,
            timestamp: message.timestamp ? new Date(message.timestamp) : new Date(),
            status: MessageStatus.DELIVERED,
            mediaUrl: message.url,
            fileName: (message.type === MessageType.FILE || message.type === MessageType.IMAGE) ? message.content : undefined,
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
      setView('login');
    }
  }, [isAuthenticated]);





  const toggleTheme = () => {
    setTheme(prev => prev === 'light' ? 'dark' : 'light');
  };

  const handleLogout = async () => {
    await logout();
    setView('login');
    setActiveChatId(null);
    setChats([]);
    setActiveTab('messages');
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

  const handleAcceptFriend = async (friendUsername: string) => {
    if (chats.some(c => c.id === friendUsername)) return;

    // Fetch public keys from server so hybrid encryption works
    let publicKeys = {};
    try {
      const resp = await api.get(`/user/${friendUsername}`);
      publicKeys = resp.data.public_keys || {};
    } catch { /* Fallback: keys will be fetched on first message */ }

    setChats(prev => {
      if (prev.some(c => c.id === friendUsername)) return prev;
      return [...prev, {
        id: friendUsername,
        participants: [{
          id: friendUsername,
          name: friendUsername,
          username: friendUsername,
          avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=' + friendUsername,
          status: 'online',
          lastSeen: 'recently',
          public_keys: publicKeys
        }],
        messages: [],
        unreadCount: 0,
        isPinned: false,
        type: 'direct'
      }];
    });
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
    return (
      <div className="flex h-screen flex-col items-center justify-center bg-[#0f172a] text-white font-sans overflow-hidden">
        <div className="fixed inset-0 pointer-events-none z-0 opacity-[0.05]"
          style={{ backgroundImage: 'linear-gradient(to right, #000 1px, transparent 1px), linear-gradient(to bottom, #000 1px, transparent 1px)', backgroundSize: '40px 40px' }} />
        
        <div className="relative mb-10 z-10">
          <div className="absolute inset-0 animate-ping rounded-full bg-emerald-500/20 blur-2xl" />
          <div className="relative z-10 w-24 h-24 bg-[#0f172a] rounded-xl p-4 border-2 border-white shadow-[8px_8px_0px_#10b981]">
            <img src="/pwa-512x512.png" alt="AGIES Logo" className="w-full h-full object-contain" />
          </div>
        </div>

        <div className="flex flex-col items-center gap-4 z-10">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 animate-bounce bg-emerald-500 rounded-full [animation-duration:0.6s]" />
            <div className="h-2 w-2 animate-bounce bg-emerald-500 rounded-full [animation-duration:0.6s] [animation-delay:0.2s]" />
            <div className="h-2 w-2 animate-bounce bg-emerald-500 rounded-full [animation-duration:0.6s] [animation-delay:0.4s]" />
          </div>
          <p className="text-[10px] font-black uppercase tracking-[0.3em] text-emerald-500 animate-pulse">Establishing Secure Vault</p>
        </div>
      </div>
    );
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
            onOpenProfile={() => setIsProfileModalOpen(true)}
            onOpenSettings={() => setIsSettingsModalOpen(true)}
            onLogout={handleLogout}
            onAcceptFriend={handleAcceptFriend}
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
        currentUser={user || { username: 'guest', id: 'guest', name: 'Guest', avatar: '' }}
      />
      <AddFriendModal
        isOpen={isAddFriendModalOpen}
        onClose={() => setIsAddFriendModalOpen(false)}
        onAdd={handleAddFriend}
        currentUser={user || undefined}
      />
      <InviteModal
        isOpen={isInviteModalOpen}
        onClose={() => setIsInviteModalOpen(false)}
        currentUser={user}
      />
      <ProfileModal
        isOpen={isProfileModalOpen}
        onClose={() => setIsProfileModalOpen(false)}
        currentUser={user}
        onLogout={handleLogout}
      />
      <SettingsModal
        isOpen={isSettingsModalOpen}
        onClose={() => setIsSettingsModalOpen(false)}
        theme={theme}
        setTheme={setTheme}
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
      <ErrorBoundary>
        <AppContent />
      </ErrorBoundary>
    </SocketProvider>
  );
};

export default App;
