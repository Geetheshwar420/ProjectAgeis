
import React, { useState, useRef, useEffect } from 'react';
import {
  MessageSquare, Users, Bell, Archive, Search, Plus,
  UserPlus, Share2, QrCode, MoreHorizontal, Pin, LogOut, Settings, User as UserIcon, Moon, Sun
} from 'lucide-react';
import Avatar from './Avatar';
import { Chat, TabType } from '../types';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';

interface LeftSidebarProps {
  chats: Chat[];
  activeChatId: string | null;
  onSelectChat: (id: string) => void;
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  onOpenQR: () => void;
  onAddFriend: () => void;
  onInvite: () => void;
  onOpenProfile: () => void;
  onOpenSettings: () => void;
  onLogout: () => void;
  onAcceptFriend: (friendUsername: string) => void;
  theme: 'light' | 'dark';
  setTheme: (theme: 'light' | 'dark') => void;
}

const LeftSidebar: React.FC<LeftSidebarProps> = ({
  chats,
  activeChatId,
  onSelectChat,
  activeTab,
  setActiveTab,
  onOpenQR,
  onAddFriend,
  onInvite,
  onOpenProfile,
  onOpenSettings,
  onLogout,
  onAcceptFriend,
  theme,
  setTheme
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [friends, setFriends] = useState<any[]>([]);
  const [friendRequests, setFriendRequests] = useState<any[]>([]);
  const [isLoadingData, setIsLoadingData] = useState(false);
  const profileMenuRef = useRef<HTMLDivElement>(null);
  const { user } = useAuth(); // Get real authenticated user

  const fetchFriends = async () => {
    if (!user) {
      console.log('[DEBUG] LeftSidebar: No user, skipping friends fetch');
      return;
    }
    try {
      setIsLoadingData(true);
      console.log('[DEBUG] LeftSidebar: Fetching friends for', user.username);
      const response = await api.get('/friends');
      console.log('[DEBUG] LeftSidebar: Friends response:', response.data);
      setFriends(response.data);
    } catch (error) {
      console.error('Error fetching friends:', error);
    } finally {
      setIsLoadingData(false);
    }
  };

  const fetchRequests = async () => {
    try {
      setIsLoadingData(true);
      const response = await api.get('/friend-requests');
      setFriendRequests(response.data);
    } catch (error) {
      console.error('Error fetching requests:', error);
    } finally {
      setIsLoadingData(false);
    }
  };

  const handleRespondRequest = async (requestId: string, status: 'accepted' | 'rejected', fromUsername: string) => {
    try {
      await api.post('/friend-request/respond', { request_id: requestId, status });
      fetchRequests();
      if (status === 'accepted') {
        fetchFriends();
        onAcceptFriend(fromUsername);
      }
    } catch (error) {
      console.error('Error responding to request:', error);
    }
  };

  useEffect(() => {
    if (user) {
      fetchFriends();
      fetchRequests();
    }
  }, [user]);

  useEffect(() => {
    if (activeTab === 'friends') fetchFriends();
    if (activeTab === 'requests') fetchRequests();
  }, [activeTab]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (profileMenuRef.current && !profileMenuRef.current.contains(event.target as Node)) {
        setShowProfileMenu(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const filteredChats = chats.filter(chat =>
    chat.participants.some(p => p.name.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const formatTime = (date: Date) => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    if (diff < 86400000) return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (diff < 604800000) return date.toLocaleDateString([], { weekday: 'short' });
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
  };

  const pinnedChats = filteredChats.filter(c => c.isPinned);
  const otherChats = filteredChats.filter(c => !c.isPinned);

  return (
    <div className="flex flex-col h-full bg-white dark:bg-black border-r-4 border-black dark:border-white font-sans selection:bg-emerald-500 selection:text-black">
      {/* Header */}
      <div className="p-4 space-y-6">
        {/* Profile Card */}
        <div className="relative" ref={profileMenuRef}>
          <div
            onClick={() => setShowProfileMenu(!showProfileMenu)}
            className="flex items-center p-3 border-4 border-black dark:border-white bg-emerald-500 transition-all cursor-pointer group shadow-[4px_4px_0px_#000] dark:shadow-[4px_4px_0px_#fff] hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0px_#000] dark:hover:shadow-[2px_2px_0px_#fff]"
          >
            <div className="border-2 border-black bg-white rounded-full">
              <Avatar
                src={`https://api.dicebear.com/7.x/avataaars/svg?seed=${user?.username || 'guest'}`}
                alt={user?.username || 'Guest'}
                status="online"
              />
            </div>
            <div className="ml-3 flex-1 min-w-0">
              <h3 className="font-black text-black uppercase tracking-tight truncate">{user?.username || 'Guest'}</h3>
              <p className="font-mono text-[10px] text-black/80 font-bold uppercase tracking-widest truncate">{user?.email || 'OFFLINE'}</p>
            </div>
            <div className={`transition-opacity ${showProfileMenu ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}>
              <MoreHorizontal className="w-5 h-5 text-black" />
            </div>
          </div>

          {/* Profile Dropdown */}
          {showProfileMenu && (
            <div className="absolute top-full left-0 right-0 mt-2 bg-white dark:bg-black border-4 border-black dark:border-white shadow-[6px_6px_0px_#10b981] py-1 z-50 animate-scale-in origin-top">
              <button
                onClick={() => {
                  setShowProfileMenu(false);
                  onOpenProfile();
                }}
                className="w-full flex items-center px-4 py-3 text-xs font-black uppercase tracking-widest text-black dark:text-white hover:bg-emerald-500 hover:text-black transition-colors"
              >
                <UserIcon className="w-4 h-4 mr-2" /> View Profile
              </button>
              <button
                onClick={() => {
                  setShowProfileMenu(false);
                  onOpenSettings();
                }}
                className="w-full flex items-center px-4 py-3 text-xs font-black uppercase tracking-widest text-black dark:text-white hover:bg-emerald-500 hover:text-black transition-colors"
              >
                <Settings className="w-4 h-4 mr-2" /> Settings
              </button>
              <button
                onClick={() => {
                  setTheme(theme === 'dark' ? 'light' : 'dark');
                  setShowProfileMenu(false);
                }}
                className="w-full flex items-center px-4 py-3 text-xs font-black uppercase tracking-widest text-black dark:text-white hover:bg-emerald-500 hover:text-black transition-colors"
              >
                {theme === 'dark' ? (
                  <><Sun className="w-4 h-4 mr-2" /> Light Mode</>
                ) : (
                  <><Moon className="w-4 h-4 mr-2" /> Dark Mode</>
                )}
              </button>
              <div className="h-1 bg-black dark:bg-white my-1"></div>
              <button
                onClick={onLogout}
                className="w-full flex items-center px-4 py-3 text-xs font-black uppercase tracking-widest text-red-600 dark:text-red-500 hover:bg-red-500 hover:text-black transition-colors"
              >
                <LogOut className="w-4 h-4 mr-2" /> Log Out
              </button>
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div className="flex justify-between gap-3">
          <button className="flex-1 flex flex-col items-center justify-center p-3 border-2 border-black dark:border-white bg-black dark:bg-white text-white dark:text-black shadow-[4px_4px_0px_#10b981] hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0px_#10b981] active:translate-x-[4px] active:translate-y-[4px] active:shadow-none transition-all">
            <MessageSquare className="w-5 h-5 mb-1" />
            <span className="text-[10px] font-black uppercase tracking-widest">New</span>
          </button>
          <button
            onClick={onAddFriend}
            className="flex-1 flex flex-col items-center justify-center p-3 border-2 border-black dark:border-white bg-white dark:bg-black text-black dark:text-white shadow-[4px_4px_0px_#10b981] hover:bg-emerald-500 hover:text-black hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0px_#10b981] active:translate-x-[4px] active:translate-y-[4px] active:shadow-none transition-all group"
          >
            <UserPlus className="w-5 h-5 mb-1 group-hover:text-black transition-colors" />
            <span className="text-[10px] font-black uppercase tracking-widest">Add</span>
          </button>
          <button
            onClick={onInvite}
            className="flex-1 flex flex-col items-center justify-center p-3 border-2 border-black dark:border-white bg-white dark:bg-black text-black dark:text-white shadow-[4px_4px_0px_#10b981] hover:bg-emerald-500 hover:text-black hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0px_#10b981] active:translate-x-[4px] active:translate-y-[4px] active:shadow-none transition-all group"
          >
            <Share2 className="w-5 h-5 mb-1 group-hover:text-black transition-colors" />
            <span className="text-[10px] font-black uppercase tracking-widest">Invite</span>
          </button>
          <button
            onClick={onOpenQR}
            className="flex-1 flex flex-col items-center justify-center p-3 border-2 border-black dark:border-white bg-white dark:bg-black text-black dark:text-white shadow-[4px_4px_0px_#10b981] hover:bg-emerald-500 hover:text-black hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0px_#10b981] active:translate-x-[4px] active:translate-y-[4px] active:shadow-none transition-all group"
          >
            <QrCode className="w-5 h-5 mb-1 group-hover:text-black transition-colors" />
            <span className="text-[10px] font-black uppercase tracking-widest">QR</span>
          </button>
        </div>

        {/* Search */}
        <div className="relative group">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-black dark:text-white group-focus-within:text-emerald-500 transition-colors" />
          <input
            type="text"
            placeholder="SEARCH_DATA..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-3 bg-transparent border-2 border-black dark:border-white rounded-none font-mono text-sm text-black dark:text-white focus:outline-none focus:border-emerald-500 placeholder-slate-400 transition-colors uppercase"
          />
        </div>

        {/* Tabs */}
        <div className="flex border-2 border-black dark:border-white bg-white dark:bg-black">
          {(['messages', 'friends', 'requests', 'archived'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex-1 py-3 text-xs font-black uppercase transition-all border-r-2 border-black dark:border-white last:border-r-0 ${activeTab === tab
                ? 'bg-emerald-500 text-black shadow-[inset_0px_-3px_0px_#000] dark:shadow-[inset_0px_-3px_0px_#fff]'
                : 'text-black dark:text-white hover:bg-black/5 dark:hover:bg-white/5'
                }`}
            >
              <div className="flex items-center justify-center">
                {tab === 'messages' && <MessageSquare className="w-4 h-4" />}
                {tab === 'friends' && <Users className="w-4 h-4" />}
                {tab === 'requests' && (
                  <div className="relative">
                    <Bell className="w-4 h-4" />
                    {friendRequests.length > 0 && (
                      <span className="absolute -top-2 -right-2 bg-red-600 text-white text-[8px] font-black px-1 border border-black rounded-sm animate-pulse">
                        {friendRequests.length}
                      </span>
                    )}
                  </div>
                )}
                {tab === 'archived' && <Archive className="w-4 h-4" />}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Chat List */}
      <div className="flex-1 overflow-y-auto custom-scrollbar">
        {activeTab === 'messages' && (
          <div className="space-y-0 relative">
            {pinnedChats.length > 0 && (
              <>
                <div className="px-4 py-2 text-[10px] font-mono font-bold text-black dark:text-white uppercase tracking-widest bg-black/5 dark:bg-white/5 border-b-2 border-black dark:border-white">Pinned Nodes</div>
                {pinnedChats.map(chat => (
                  <ChatItem
                    key={chat.id}
                    chat={chat}
                    active={chat.id === activeChatId}
                    onClick={() => onSelectChat(chat.id)}
                    timeStr={chat.messages && chat.messages.length > 0 ? formatTime(chat.messages[chat.messages.length - 1].timestamp) : ''}
                  />
                ))}
                <div className="border-b-4 border-black dark:border-white"></div>
              </>
            )}

            <div className="px-4 py-2 text-[10px] font-mono font-bold text-black dark:text-white uppercase tracking-widest bg-black/5 dark:bg-white/5 border-b-2 border-black dark:border-white">Active Connections</div>
            {otherChats.map(chat => (
              <ChatItem
                key={chat.id}
                chat={chat}
                active={chat.id === activeChatId}
                onClick={() => onSelectChat(chat.id)}
                timeStr={chat.messages && chat.messages.length > 0 ? formatTime(chat.messages[chat.messages.length - 1].timestamp) : ''}
              />
            ))}

            {filteredChats.length === 0 && (
              <div className="text-center py-10 font-mono text-xs uppercase tracking-widest text-slate-500">
                <p>[ ERROR: NO_DATA_FOUND ]</p>
              </div>
            )}
          </div>
        )}
        {/* Placeholders for other tabs */}
        {activeTab === 'friends' && (
          <div className="space-y-0 relative animate-fade-in">
            <div className="px-4 py-2 text-[10px] font-mono font-bold text-black dark:text-white uppercase tracking-widest bg-black/5 dark:bg-white/5 border-b-2 border-black dark:border-white">
              Authorized Contacts ({friends.length})
            </div>
            {friends.map(friend => (
              <div key={friend.id} className="p-4 border-b-2 border-black dark:border-white hover:bg-emerald-50 dark:hover:bg-emerald-900/10 cursor-pointer transition-all flex items-center gap-4">
                <div className="border-2 border-black bg-white rounded-full">
                  <Avatar
                    src={`https://api.dicebear.com/7.x/avataaars/svg?seed=${friend.username}`}
                    alt={friend.username}
                    status={friend.is_online ? 'online' : 'offline'}
                  />
                </div>
                <div className="flex-1 min-w-0">
                  <h4 className="font-black text-black dark:text-white uppercase truncate">{friend.username}</h4>
                  <p className="font-mono text-[10px] text-slate-500 uppercase tracking-widest truncate">LINK_STABLE</p>
                </div>
                <button
                  onClick={() => { onSelectChat(friend.username); setActiveTab('messages'); }}
                  className="p-2 border-2 border-black dark:border-white bg-white dark:bg-black text-black dark:text-white hover:bg-emerald-500 transition-colors"
                >
                  <MessageSquare className="w-4 h-4" />
                </button>
              </div>
            ))}
            {friends.length === 0 && !isLoadingData && (
              <div className="p-8 text-center font-mono text-xs uppercase tracking-widest text-slate-500">[ VAULT_EMPTY ]</div>
            )}
          </div>
        )}

        {activeTab === 'requests' && (
          <div className="space-y-0 relative animate-fade-in">
            <div className="px-4 py-2 text-[10px] font-mono font-bold text-black dark:text-white uppercase tracking-widest bg-black/5 dark:bg-white/5 border-b-2 border-black dark:border-white">
              Incoming Transmission Requests ({friendRequests.length})
            </div>
            {friendRequests.map(req => (
              <div key={req.id} className="p-4 border-b-2 border-black dark:border-white bg-teal-50/50 dark:bg-teal-900/5 transition-all">
                <div className="flex items-center gap-4 mb-3">
                  <div className="w-10 h-10 border-2 border-black bg-white rounded-full flex items-center justify-center">
                    <UserIcon className="w-6 h-6 text-black" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <h4 className="font-black text-black dark:text-white uppercase truncate">{req.from_username}</h4>
                    <p className="font-mono text-[10px] text-slate-500 uppercase tracking-widest">AWAIT_APPROVAL</p>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => handleRespondRequest(req.id, 'accepted', req.from_username)}
                    className="flex-1 py-1.5 border-2 border-black bg-emerald-500 text-black font-black uppercase text-[10px] tracking-widest hover:translate-x-[1px] hover:translate-y-[1px] shadow-[2px_2px_0px_#000] active:shadow-none transition-all"
                  >
                    Authorize
                  </button>
                  <button
                    onClick={() => handleRespondRequest(req.id, 'rejected', req.from_username)}
                    className="flex-1 py-1.5 border-2 border-black bg-white text-black font-black uppercase text-[10px] tracking-widest hover:translate-x-[1px] hover:translate-y-[1px] shadow-[2px_2px_0px_#000] active:shadow-none transition-all"
                  >
                    Deny
                  </button>
                </div>
              </div>
            ))}
            {friendRequests.length === 0 && !isLoadingData && (
              <div className="p-8 text-center font-mono text-xs uppercase tracking-widest text-slate-500">[ QUEUE_EMPTY ]</div>
            )}
          </div>
        )}

        {activeTab === 'archived' && <div className="p-8 pb-0 text-center font-mono text-xs uppercase tracking-widest text-slate-500">[ VAULT_EMPTY: NO_ARCHIVES ]</div>}
      </div>
    </div >
  );
};

const ChatItem: React.FC<{ chat: Chat; active: boolean; onClick: () => void; timeStr: string }> = ({ chat, active, onClick, timeStr }) => {
  const lastMsg = chat.messages && chat.messages.length > 0 ? chat.messages[chat.messages.length - 1] : null;
  const participant = chat.participants && chat.participants.length > 0
    ? chat.participants[0]
    : { id: 'unknown', name: 'Unknown User', avatar: '', status: 'offline' };

  return (
    <div
      onClick={onClick}
      className={`relative group p-4 border-b-2 border-black dark:border-white cursor-pointer transition-all duration-200 
        ${active
          ? 'bg-emerald-500/10'
          : 'hover:bg-black/5 dark:hover:bg-white/5'
        }
      `}
    >
      <div className="flex items-start">
        <div className="bg-white rounded-full border-2 border-black">
          <Avatar src={participant.avatar} alt={participant.name} status={participant.status as any} size="md" />
        </div>
        <div className="ml-3 flex-1 min-w-0">
          <div className="flex justify-between items-baseline">
            <h4 className={`text-sm font-black uppercase tracking-tight truncate text-black dark:text-white`}>
              {participant.name}
            </h4>
            <span className={`text-[10px] font-mono tracking-widest uppercase ${chat.unreadCount > 0 ? 'text-emerald-600 dark:text-emerald-400 font-bold' : 'text-slate-500'}`}>
              {timeStr}
            </span>
          </div>
          <p className={`text-xs truncate mt-1 font-mono uppercase tracking-wider ${chat.unreadCount > 0 ? 'text-black dark:text-white font-bold' : 'text-slate-500'}`}>
            {lastMsg ? (
              <>
                {lastMsg.senderId === 'me' && <span className="mr-1 text-emerald-600 dark:text-emerald-400">ACK:</span>}
                {lastMsg.type === 'image' ? '[MEDIA_PAYLOAD]' : lastMsg.type === 'file' ? '[DATA_FILE]' : lastMsg.content}
              </>
            ) : (
              <span className="text-slate-500 italic">[EMPTY_LOG]</span>
            )}
          </p>
        </div>

        {/* Indicators */}
        <div className="flex flex-col items-end justify-center gap-2 ml-3">
          {chat.isPinned && <Pin className="w-4 h-4 text-black dark:text-white rotate-45" />}
          {chat.unreadCount > 0 && (
            <span className="flex items-center justify-center w-6 h-6 border-2 border-black dark:border-white bg-emerald-500 text-black text-[10px] font-black shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff]">
              {chat.unreadCount}
            </span>
          )}
        </div>
      </div>
      {active && <div className="absolute left-0 top-0 bottom-0 w-2 bg-emerald-500 border-r-2 border-black dark:border-white" />}
    </div>
  );
};

export default LeftSidebar;
