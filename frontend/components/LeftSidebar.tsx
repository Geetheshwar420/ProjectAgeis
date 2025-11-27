
import React, { useState, useRef, useEffect } from 'react';
import {
  MessageSquare, Users, Bell, Archive, Search, Plus,
  UserPlus, Share2, QrCode, MoreHorizontal, Pin, LogOut, Settings, User, Moon, Sun
} from 'lucide-react';
import Avatar from './Avatar';
import { Chat, TabType } from '../types';
import { useAuth } from '../context/AuthContext';

interface LeftSidebarProps {
  chats: Chat[];
  activeChatId: string | null;
  onSelectChat: (id: string) => void;
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  onOpenQR: () => void;
  onAddFriend: () => void;
  onInvite: () => void;
  onLogout: () => void;
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
  onLogout,
  theme,
  setTheme
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const profileMenuRef = useRef<HTMLDivElement>(null);
  const { user } = useAuth(); // Get real authenticated user

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
    <div className="flex flex-col h-full bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl border-r border-gray-200 dark:border-gray-800">
      {/* Header */}
      <div className="p-4 space-y-4">
        {/* Profile Card */}
        <div className="relative" ref={profileMenuRef}>
          <div
            onClick={() => setShowProfileMenu(!showProfileMenu)}
            className="flex items-center p-3 rounded-xl bg-gradient-to-r from-teal-500/10 to-purple-500/10 hover:from-teal-500/20 hover:to-purple-500/20 transition-all cursor-pointer group border border-transparent hover:border-teal-500/30"
          >
            <Avatar
              src={`https://api.dicebear.com/7.x/avataaars/svg?seed=${user?.username || 'guest'}`}
              alt={user?.username || 'Guest'}
              status="online"
            />
            <div className="ml-3 flex-1 min-w-0">
              <h3 className="font-bold text-gray-900 dark:text-white truncate">{user?.username || 'Guest'}</h3>
              <p className="text-xs text-gray-500 dark:text-gray-400 truncate">{user?.email || 'Not logged in'}</p>
            </div>
            <div className={`transition-opacity ${showProfileMenu ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}>
              <MoreHorizontal className="w-5 h-5 text-gray-500" />
            </div>
          </div>

          {/* Profile Dropdown */}
          {showProfileMenu && (
            <div className="absolute top-full left-0 right-0 mt-2 bg-white dark:bg-slate-800 rounded-xl shadow-xl border border-gray-200 dark:border-gray-700 py-1 z-50 animate-scale-in origin-top">
              <button
                onClick={() => {
                  setShowProfileMenu(false);
                  // TODO: Navigate to profile page
                  alert('Profile page coming soon!');
                }}
                className="w-full flex items-center px-4 py-2.5 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-slate-700 transition-colors"
              >
                <User className="w-4 h-4 mr-2" /> View Profile
              </button>
              <button
                onClick={() => {
                  setShowProfileMenu(false);
                  // TODO: Navigate to settings page
                  alert('Settings page coming soon!');
                }}
                className="w-full flex items-center px-4 py-2.5 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-slate-700 transition-colors"
              >
                <Settings className="w-4 h-4 mr-2" /> Settings
              </button>
              <button
                onClick={() => {
                  setTheme(theme === 'dark' ? 'light' : 'dark');
                  setShowProfileMenu(false);
                }}
                className="w-full flex items-center px-4 py-2.5 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-slate-700 transition-colors"
              >
                {theme === 'dark' ? (
                  <><Sun className="w-4 h-4 mr-2" /> Light Mode</>
                ) : (
                  <><Moon className="w-4 h-4 mr-2" /> Dark Mode</>
                )}
              </button>
              <div className="h-px bg-gray-100 dark:bg-gray-700 my-1"></div>
              <button
                onClick={onLogout}
                className="w-full flex items-center px-4 py-2.5 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/10 transition-colors"
              >
                <LogOut className="w-4 h-4 mr-2" /> Log Out
              </button>
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div className="flex justify-between gap-2">
          <button className="flex-1 flex flex-col items-center justify-center p-2 rounded-lg bg-teal-500 text-white shadow-lg shadow-teal-500/30 hover:scale-105 transition-transform">
            <MessageSquare className="w-5 h-5 mb-1" />
            <span className="text-[10px] font-medium">New Chat</span>
          </button>
          <button
            onClick={onAddFriend}
            className="flex-1 flex flex-col items-center justify-center p-2 rounded-lg bg-white dark:bg-slate-800 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-slate-700 transition-colors"
          >
            <UserPlus className="w-5 h-5 mb-1 text-teal-600 dark:text-teal-400" />
            <span className="text-[10px] text-gray-600 dark:text-gray-300">Add</span>
          </button>
          <button
            onClick={onInvite}
            className="flex-1 flex flex-col items-center justify-center p-2 rounded-lg bg-white dark:bg-slate-800 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-slate-700 transition-colors"
          >
            <Share2 className="w-5 h-5 mb-1 text-purple-600 dark:text-purple-400" />
            <span className="text-[10px] text-gray-600 dark:text-gray-300">Invite</span>
          </button>
          <button
            onClick={onOpenQR}
            className="flex-1 flex flex-col items-center justify-center p-2 rounded-lg bg-white dark:bg-slate-800 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-slate-700 transition-colors"
          >
            <QrCode className="w-5 h-5 mb-1 text-gray-600 dark:text-gray-400" />
            <span className="text-[10px] text-gray-600 dark:text-gray-300">QR</span>
          </button>
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search messages..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 bg-gray-100 dark:bg-slate-800 rounded-full text-sm focus:outline-none focus:ring-2 focus:ring-teal-500/50 transition-all dark:text-white placeholder-gray-500"
          />
        </div>

        {/* Tabs */}
        <div className="flex p-1 bg-gray-100 dark:bg-slate-800 rounded-lg">
          {(['messages', 'friends', 'requests', 'archived'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex-1 py-1.5 rounded-md text-xs font-medium transition-all ${activeTab === tab
                ? 'bg-white dark:bg-slate-700 text-teal-600 dark:text-teal-400 shadow-sm'
                : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
                }`}
            >
              <div className="flex items-center justify-center">
                {tab === 'messages' && <MessageSquare className="w-4 h-4" />}
                {tab === 'friends' && <Users className="w-4 h-4" />}
                {tab === 'requests' && <Bell className="w-4 h-4" />}
                {tab === 'archived' && <Archive className="w-4 h-4" />}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Chat List */}
      <div className="flex-1 overflow-y-auto custom-scrollbar">
        {activeTab === 'messages' && (
          <div className="space-y-1 p-2">
            {pinnedChats.length > 0 && (
              <>
                <div className="px-3 py-1 text-xs font-semibold text-gray-400 uppercase tracking-wider">Pinned</div>
                {pinnedChats.map(chat => (
                  <ChatItem
                    key={chat.id}
                    chat={chat}
                    active={chat.id === activeChatId}
                    onClick={() => onSelectChat(chat.id)}
                    timeStr={chat.messages.length > 0 ? formatTime(chat.messages[chat.messages.length - 1].timestamp) : ''}
                  />
                ))}
                <div className="my-2 border-b border-gray-100 dark:border-gray-800"></div>
              </>
            )}

            <div className="px-3 py-1 text-xs font-semibold text-gray-400 uppercase tracking-wider">Recent</div>
            {otherChats.map(chat => (
              <ChatItem
                key={chat.id}
                chat={chat}
                active={chat.id === activeChatId}
                onClick={() => onSelectChat(chat.id)}
                timeStr={chat.messages.length > 0 ? formatTime(chat.messages[chat.messages.length - 1].timestamp) : ''}
              />
            ))}

            {filteredChats.length === 0 && (
              <div className="text-center py-10 text-gray-400">
                <p>No conversations found</p>
              </div>
            )}
          </div>
        )}
        {/* Placeholders for other tabs */}
        {activeTab === 'friends' && <div className="p-8 text-center text-gray-500">Friends list coming soon</div>}
        {activeTab === 'requests' && <div className="p-8 text-center text-gray-500">No pending requests</div>}
        {activeTab === 'archived' && <div className="p-8 text-center text-gray-500">No archived chats</div>}
      </div>
    </div>
  );
};

const ChatItem: React.FC<{ chat: Chat; active: boolean; onClick: () => void; timeStr: string }> = ({ chat, active, onClick, timeStr }) => {
  const lastMsg = chat.messages.length > 0 ? chat.messages[chat.messages.length - 1] : null;
  const participant = chat.participants[0];

  return (
    <div
      onClick={onClick}
      className={`relative group p-3 rounded-xl cursor-pointer transition-all duration-200 border border-transparent
        ${active
          ? 'bg-teal-500/10 border-teal-500/20'
          : 'hover:bg-gray-50 dark:hover:bg-slate-800/50'
        }
      `}
    >
      <div className="flex items-start">
        <Avatar src={participant.avatar} alt={participant.name} status={participant.status as any} size="md" />
        <div className="ml-3 flex-1 min-w-0">
          <div className="flex justify-between items-baseline">
            <h4 className={`text-sm font-semibold truncate ${active ? 'text-teal-700 dark:text-teal-400' : 'text-gray-900 dark:text-white'}`}>
              {participant.name}
            </h4>
            <span className={`text-[11px] ${chat.unreadCount > 0 ? 'text-teal-600 font-medium' : 'text-gray-400'}`}>
              {timeStr}
            </span>
          </div>
          <p className={`text-xs truncate mt-0.5 ${chat.unreadCount > 0 ? 'text-gray-900 dark:text-white font-medium' : 'text-gray-500'}`}>
            {lastMsg ? (
              <>
                {lastMsg.senderId === 'me' && <span className="mr-1">You:</span>}
                {lastMsg.type === 'image' ? '📷 Photo' : lastMsg.type === 'file' ? '📎 File' : lastMsg.content}
              </>
            ) : (
              <span className="text-gray-400">No messages yet</span>
            )}
          </p>
        </div>

        {/* Indicators */}
        <div className="flex flex-col items-end gap-1 ml-2">
          {chat.isPinned && <Pin className="w-3 h-3 text-gray-400 rotate-45" />}
          {chat.unreadCount > 0 && (
            <span className="flex items-center justify-center w-5 h-5 rounded-full bg-teal-500 text-white text-[10px] font-bold shadow-md shadow-teal-500/20">
              {chat.unreadCount}
            </span>
          )}
        </div>
      </div>
      {active && <div className="absolute left-0 top-3 bottom-3 w-1 bg-teal-500 rounded-r-full" />}
    </div>
  );
};

export default LeftSidebar;
