import React, { useState, useEffect, useRef } from 'react';
import {
   X, UserPlus, Copy, Share2, Mail, Link as LinkIcon, Check,
   Search, Clock, ChevronRight, User as UserIcon, Users, Calendar, ArrowRight,
   MessageSquare, MoreHorizontal, Shield, Smartphone,
   Moon, Sun, Settings as SettingsIcon, LogOut
} from 'lucide-react';
import Avatar from './Avatar';
import { User as UserType } from '../types';
import api from '../services/api';

// --- Add Friend Modal ---

interface AddFriendModalProps {
   isOpen: boolean;
   onClose: () => void;
   onAdd: (username: string) => void;
   currentUser?: { username: string };
}

export const AddFriendModal: React.FC<AddFriendModalProps> = ({ isOpen, onClose, onAdd, currentUser }) => {
   const [searchQuery, setSearchQuery] = useState('');
   const [isSearching, setIsSearching] = useState(false);
   const [searchResults, setSearchResults] = useState<any[]>([]);
   const [hasSearched, setHasSearched] = useState(false);
   const [recentSearches, setRecentSearches] = useState<{ username: string, time: string }[]>([]);
   const [friendRequestsSent, setFriendRequestsSent] = useState<Set<string>>(new Set());

   // Debounced Search with real API
   useEffect(() => {
      // Immediate visual feedback that search is initiating
      if (searchQuery.length >= 2) {
         setIsSearching(true);
      } else {
         setIsSearching(false);
         setSearchResults([]);
         setHasSearched(false);
      }

      const timer = setTimeout(async () => {
         if (searchQuery.length >= 2) {
            try {
               const response = await api.get('/users');
               let results = response.data.filter((user: any) =>
                  user.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
                  (user.email && user.email.toLowerCase().includes(searchQuery.toLowerCase()))
               );
               if (currentUser) {
                  results = results.filter((u: any) => u.username !== currentUser.username);
               }

               // Deduplicate results by username in case backend returns distinct entries that match both
               const uniqueResults = Array.from(new Map(results.map((item: any) => [item.username, item])).values());

               setSearchResults(uniqueResults);
               setHasSearched(true);
            } catch (error) {
               console.error('Failed to search users:', error);
               setSearchResults([]);
            } finally {
               setIsSearching(false);
            }
         }
      }, 250); // Reduced delay for snappier feel

      return () => clearTimeout(timer);
   }, [searchQuery]);

   if (!isOpen) return null;

   const handleSendRequest = (userId: string, username: string) => {
      // Pass to parent handler which calls real API
      onAdd(username);

      // Update local state for immediate UI feedback
      setFriendRequestsSent(prev => new Set(prev).add(userId));

      // Add to recent searches if not exists
      if (!recentSearches.find(r => r.username === username)) {
         setRecentSearches(prev => [{ username, time: 'Just now' }, ...prev].slice(0, 5));
      }
   };

   const clearRecent = () => setRecentSearches([]);

   const removeRecent = (username: string) => {
      setRecentSearches(prev => prev.filter(r => r.username !== username));
   };

   return (
      <div className="fixed inset-0 z-[100] flex items-center justify-center p-0 md:p-4">
         <div className="absolute inset-0 bg-black/60  transition-opacity" onClick={onClose} />

         <div className="relative w-full h-full md:h-auto md:max-h-[700px] md:w-[600px] bg-white dark:bg-black md:rounded-none shadow-[8px_8px_0px_#000] dark:shadow-[8px_8px_0px_#fff] flex flex-col overflow-hidden animate-scale-in">

            {/* Header (Sticky) */}
            <div className="flex-shrink-0 h-16 flex items-center justify-between px-4 border-b border-black dark:border-white dark:border-black dark:border-white bg-emerald-500  z-20">
               <div className="w-10"></div> {/* Spacer */}
               <div className="flex flex-col items-center">
                  <div className="flex items-center gap-2">
                     <UserPlus className="w-5 h-5 text-black dark:text-white" />
                     <h2 className="text-lg font-black text-black uppercase tracking-tighter dark:text-white">Add New Friend</h2>
                  </div>
               </div>
               <button
                  onClick={onClose}
                  className="w-10 h-10 flex items-center justify-center rounded-none hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors"
               >
                  <X className="w-6 h-6 text-black dark:text-white" />
               </button>
            </div>

            {/* Search Input Area */}
            <div className="flex-shrink-0 p-5 bg-white dark:bg-black z-10">
               <div className={`relative flex items-center transition-all duration-200 rounded-none border-2 ${isSearching || searchQuery ? 'border-black dark:border-white bg-white dark:bg-gray-900' : 'border-black dark:border-white bg-gray-100 dark:bg-gray-900'}`}>
                  <div className="absolute left-4 flex items-center pointer-events-none">
                     {isSearching ? (
                        <div className="w-5 h-5 border-2 border-black dark:border-white/30 border-t-teal-500 rounded-none animate-spin" />
                     ) : (
                        <Search className={`w-5 h-5 ${searchQuery ? 'text-black dark:text-white' : 'text-neutral-500'}`} />
                     )}
                  </div>
                  <input
                     id="friend-search-input"
                     aria-label="Search for friends by username or email"
                     type="text"
                     value={searchQuery}
                     onChange={(e) => setSearchQuery(e.target.value.replace(/\s/g, ''))} // No spaces
                     placeholder="username or email"
                     className="w-full py-3.5 pl-12 pr-10 bg-transparent border-none focus:ring-0 text-gray-900 dark:text-white placeholder-gray-400 text-base"
                     autoFocus
                  />
                  {searchQuery && (
                     <button
                        onClick={() => setSearchQuery('')}
                        className="absolute right-3 p-1 rounded-none text-neutral-500 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/10 transition-colors"
                     >
                        <X className="w-4 h-4" />
                     </button>
                  )}
               </div>
            </div>

            {/* Tab Navigation (only if no search query) */}
            {!searchQuery && (
               <div className="flex px-5 border-b border-black dark:border-white dark:border-black dark:border-white">
                  <div className="flex-1 pb-3 text-sm font-medium text-black dark:text-white dark:text-black dark:text-white relative">
                     Recent Searches
                     <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-teal-500 rounded-t-full" />
                  </div>
               </div>
            )}

            {/* Content Area */}
            <div className="flex-1 overflow-y-auto custom-scrollbar p-5">

               {/* Case 1: Searching / Loading */}
               {isSearching && (
                  <div className="space-y-4">
                     {[1, 2, 3].map(i => (
                        <div key={i} className="flex items-center p-4 rounded-none bg-gray-50 dark:bg-gray-900/50 animate-pulse">
                           <div className="w-14 h-14 rounded-none bg-gray-200 dark:bg-gray-800" />
                           <div className="ml-4 flex-1">
                              <div className="h-4 w-32 bg-gray-200 dark:bg-gray-800 rounded mb-2" />
                              <div className="h-3 w-24 bg-gray-200 dark:bg-gray-800 rounded" />
                           </div>
                        </div>
                     ))}
                  </div>
               )}

               {/* Case 2: Search Results Found */}
               {!isSearching && searchQuery && searchResults.length > 0 && (
                  <div className="space-y-3 animate-fade-in">
                     <h3 className="text-xs font-bold text-black dark:text-white uppercase tracking-wider mb-2">Search Results</h3>
                     {searchResults.map(user => (
                        <UserResultCard
                           key={user.id}
                           user={user}
                           searchQuery={searchQuery}
                           isRequestSent={friendRequestsSent.has(user.id)}
                           onSendRequest={() => handleSendRequest(user.id, user.username)}
                        />
                     ))}
                  </div>
               )}

               {/* Case 3: No Results - Invite Flow */}
               {!isSearching && hasSearched && searchResults.length === 0 && (
                  <div className="flex flex-col items-center justify-center py-8 animate-fade-in">
                     <div className="relative mb-6">
                        <div className="w-24 h-24 bg-gray-100 dark:bg-gray-900 rounded-none flex items-center justify-center animate-bounce-soft">
                           <Search className="w-10 h-10 text-neutral-500" />
                        </div>
                        <div className="absolute -top-1 -right-1 w-8 h-8 bg-teal-100 dark:bg-teal-900/50 rounded-none flex items-center justify-center border-4 border-white dark:border-slate-900">
                           <div className="text-black dark:text-white dark:text-black dark:text-white font-bold text-lg">?</div>
                        </div>
                     </div>

                     <h3 className="text-xl font-black text-black uppercase tracking-tighter dark:text-white mb-2">No users found</h3>
                     <p className="text-black dark:text-white text-center max-w-xs mb-8">
                        We couldn't find anyone with the username <span className="text-black dark:text-white font-mono">@{searchQuery}</span>
                     </p>

                     {/* Invite Card */}
                     <div className="w-full bg-gradient-to-br from-teal-50 to-purple-50 dark:from-teal-900/20 dark:to-purple-900/20 border border-teal-100 dark:border-teal-800/30 rounded-none p-6 relative overflow-hidden group">
                        <div className="absolute top-0 right-0 w-32 h-32 bg-teal-500/10 rounded-none blur-3xl -mr-16 -mt-16 transition-all group-hover:bg-teal-500/20" />

                        <div className="flex items-center gap-4 mb-4">
                           <div className="w-12 h-12 bg-white dark:bg-gray-900 rounded-none flex items-center justify-center shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff]">
                              <Share2 className="w-6 h-6 text-black dark:text-white dark:text-black dark:text-white" />
                           </div>
                           <div>
                              <h4 className="font-black text-black uppercase tracking-tighter dark:text-white">Invite to AGES</h4>
                              <p className="text-xs text-black dark:text-white">Send them an invite link</p>
                           </div>
                        </div>

                        <div className="bg-white dark:bg-gray-900 rounded-none border border-black dark:border-white dark:border-black dark:border-white flex items-center justify-between p-1 pl-4 mb-4">
                           <span className="text-sm text-black dark:text-white font-mono truncate mr-2">
                              ages.app/invite/{searchQuery}
                           </span>
                           <button className="p-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-slate-600 rounded-none transition-colors">
                              <Copy className="w-4 h-4 text-gray-600 dark:text-gray-300" />
                           </button>
                        </div>

                        <div className="flex gap-2 justify-center">
                           <button className="flex-1 py-2 bg-green-500 hover:bg-green-600 text-white rounded-none text-sm font-medium transition-colors flex items-center justify-center gap-2">
                              <MessageSquare className="w-4 h-4" /> WhatsApp
                           </button>
                           <button className="flex-1 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-none text-sm font-medium transition-colors flex items-center justify-center gap-2">
                              <Mail className="w-4 h-4" /> Email
                           </button>
                        </div>
                     </div>

                     <div className="mt-8 w-full">
                        <h4 className="text-xs font-bold text-neutral-500 uppercase tracking-wider mb-3">Suggestions</h4>
                        <ul className="text-sm text-black dark:text-white space-y-2">
                           <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 bg-gray-300 rounded-none" /> Check spelling of the username</li>
                           <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 bg-gray-300 rounded-none" /> Ask them to share their QR code</li>
                        </ul>
                     </div>
                  </div>
               )}

               {/* Case 4: Recent Searches (Default Tab) */}
               {!searchQuery && (
                  <div className="animate-fade-in">
                     {recentSearches.length > 0 ? (
                        <>
                           <div className="flex items-center justify-between mb-2">
                              <h3 className="text-xs font-bold text-black dark:text-white uppercase tracking-wider">Recent</h3>
                              <button onClick={clearRecent} className="text-xs text-black dark:text-white hover:text-teal-700">Clear All</button>
                           </div>
                           <div className="space-y-1">
                              {recentSearches.map((item, idx) => (
                                 <div key={idx} className="group flex items-center justify-between p-3 hover:bg-gray-50 dark:hover:bg-gray-900 rounded-none transition-colors cursor-pointer" onClick={() => setSearchQuery(item.username.replace('@', ''))}>
                                    <div className="flex items-center gap-3">
                                       <div className="w-10 h-10 rounded-none bg-gray-100 dark:bg-gray-900 flex items-center justify-center">
                                          <Clock className="w-5 h-5 text-neutral-500" />
                                       </div>
                                       <div>
                                          <p className="font-medium text-gray-900 dark:text-white">{item.username}</p>
                                          <p className="text-xs text-black dark:text-white">{item.time}</p>
                                       </div>
                                    </div>
                                    <button
                                       onClick={(e) => { e.stopPropagation(); removeRecent(item.username); }}
                                       className="p-2 opacity-0 group-hover:opacity-100 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-none text-neutral-500 hover:text-red-500 transition-all"
                                    >
                                       <X className="w-4 h-4" />
                                    </button>
                                 </div>
                              ))}
                           </div>
                        </>
                     ) : (
                        <div className="flex flex-col items-center justify-center py-12 text-neutral-500">
                           <Clock className="w-12 h-12 mb-4 opacity-20" />
                           <p>No recent searches</p>
                        </div>
                     )}
                  </div>
               )}

            </div>

            {/* Footer */}
            <div className="p-4 border-t border-black dark:border-white dark:border-black dark:border-white bg-gray-50 dark:bg-black/50 flex justify-center">
               <p className="text-xs text-neutral-500 flex items-center gap-1">
                  <Shield className="w-3 h-3" /> Your searches are private and encrypted
               </p>
            </div>
         </div>
      </div>
   );
};

// Helper Component for Search Result Card
const UserResultCard: React.FC<{
   user: any,
   searchQuery: string,
   isRequestSent: boolean,
   onSendRequest: () => void
}> = ({ user, searchQuery, isRequestSent, onSendRequest }) => {

   return (
      <div className="group relative flex items-center p-4 rounded-none bg-white dark:bg-gray-900 border border-black dark:border-white hover:border-black dark:border-white/30 hover:shadow-[6px_6px_0px_#000] dark:shadow-[6px_6px_0px_#fff] hover:shadow-teal-500/5 transition-all duration-300">
         <div className={`absolute left-0 top-4 bottom-4 w-1 bg-teal-500 rounded-r-full transform scale-y-0 group-hover:scale-y-100 transition-transform origin-center`} />

         <div className="relative">
            <Avatar
               src={`https://api.dicebear.com/7.x/avataaars/svg?seed=${user.username}`}
               alt={user.username}
               size="md"
               status={user.is_online ? 'online' : 'offline'}
            />
         </div>

         <div className="ml-4 flex-1 min-w-0">
            <div className="flex items-baseline gap-2">
               <h4 className="text-sm font-black text-black uppercase tracking-tighter dark:text-white truncate">{user.username}</h4>
               <span className="text-xs text-black dark:text-white truncate">{user.email}</span>
            </div>

            <div className="flex items-center gap-3 mt-1 text-xs text-black dark:text-white">
               <span className="flex items-center">
                  <Calendar className="w-3 h-3 mr-1" /> User on platform
               </span>
            </div>
         </div>

         <div className="ml-4">
            {isRequestSent ? (
               <button disabled className="flex items-center px-4 py-2 bg-gray-100 dark:bg-gray-800 text-black dark:text-white rounded-none text-sm font-medium cursor-default">
                  <Check className="w-4 h-4 mr-1.5" /> Sent
               </button>
            ) : (
               <button
                  onClick={onSendRequest}
                  className="flex items-center px-4 py-2 bg-gradient-to-r from-teal-500 to-teal-600 hover:from-teal-600 hover:to-teal-700 text-white rounded-none text-sm font-medium shadow-[4px_4px_0px_#000] dark:shadow-[4px_4px_0px_#fff] shadow-teal-500/20 transform active:scale-95 transition-all"
               >
                  <UserPlus className="w-4 h-4 mr-1.5" /> Add
               </button>
            )}
         </div>
      </div>
   );
};


// --- Invite Modal ---

interface InviteModalProps {
   isOpen: boolean;
   onClose: () => void;
   currentUser: { username: string };
}

export const InviteModal: React.FC<InviteModalProps> = ({ isOpen, onClose, currentUser }) => {
   const [copied, setCopied] = useState(false);
   const inviteLink = `https://ages.app/invite/${currentUser.username.replace('@', '')}`;

   if (!isOpen) return null;

   const handleCopy = () => {
      navigator.clipboard.writeText(inviteLink);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
   };

   return (
      <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
         <div className="absolute inset-0 bg-black/70 " onClick={onClose} />

         <div className="relative w-full max-w-md bg-white dark:bg-black rounded-none shadow-[8px_8px_0px_#000] dark:shadow-[8px_8px_0px_#fff] p-0 border border-white/10 animate-scale-in overflow-hidden">
            {/* Header */}
            <div className="relative h-32 bg-gradient-to-br from-purple-600 to-indigo-600 p-6 flex flex-col items-center justify-center text-center">
               <button onClick={onClose} className="absolute top-4 right-4 p-2 bg-black/20 hover:bg-black/30 rounded-none text-white transition-colors">
                  <X className="w-4 h-4" />
               </button>
               <div className="w-16 h-16 bg-white rounded-none shadow-[6px_6px_0px_#000] dark:shadow-[6px_6px_0px_#fff] flex items-center justify-center transform translate-y-8 rotate-3">
                  <Share2 className="w-8 h-8 text-purple-600" />
               </div>
            </div>

            <div className="pt-12 pb-8 px-6 text-center">
               <h2 className="text-2xl font-black text-black uppercase tracking-tighter dark:text-white mb-2">Invite Friends</h2>
               <p className="text-black dark:text-white text-sm mb-8">Share this link to connect securely on AGES.</p>

               {/* Link Box */}
               <div className="bg-gray-50 dark:bg-gray-900 p-2 rounded-none border border-black dark:border-white dark:border-black dark:border-white flex items-center justify-between gap-2 mb-8 shadow-inner">
                  <div className="flex-1 px-3 py-2 overflow-hidden">
                     <p className="text-xs text-neutral-500 font-semibold uppercase tracking-wider mb-0.5">Your Invite Link</p>
                     <p className="text-sm font-mono text-gray-800 dark:text-gray-200 truncate">{inviteLink}</p>
                  </div>
                  <button
                     onClick={handleCopy}
                     className={`p-3 rounded-none transition-all duration-300 ${copied ? 'bg-green-500 text-white' : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-slate-600 shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff]'}`}
                  >
                     {copied ? <Check className="w-5 h-5" /> : <Copy className="w-5 h-5" />}
                  </button>
               </div>

               {/* Social Grid */}
               <div className="grid grid-cols-4 gap-4 mb-4">
                  <SocialButton icon={<MessageSquare className="w-5 h-5" />} label="SMS" color="bg-green-500" />
                  <SocialButton icon={<Mail className="w-5 h-5" />} label="Email" color="bg-blue-500" />
                  <SocialButton icon={<Smartphone className="w-5 h-5" />} label="WhatsApp" color="bg-green-600" />
                  <SocialButton icon={<MoreHorizontal className="w-5 h-5" />} label="More" color="bg-gray-500" />
               </div>
            </div>
         </div>
      </div>
   );
};

const SocialButton: React.FC<{ icon: React.ReactNode, label: string, color: string }> = ({ icon, label, color }) => (
   <button className="flex flex-col items-center gap-2 group">
      <div className={`w-12 h-12 rounded-none ${color} text-white flex items-center justify-center shadow-[4px_4px_0px_#000] dark:shadow-[4px_4px_0px_#fff] transform transition-transform group-hover:scale-110 group-active:scale-95`}>
         {icon}
      </div>
      <span className="text-xs font-medium text-gray-600 dark:text-neutral-500">{label}</span>
   </button>
);

// --- Profile Modal ---
interface ProfileModalProps {
   isOpen: boolean;
   onClose: () => void;
   currentUser: any;
   onLogout: () => void;
}

export const ProfileModal: React.FC<ProfileModalProps> = ({ isOpen, onClose, currentUser, onLogout }) => {
   if (!isOpen || !currentUser) return null;

   const joinDate = currentUser.created_at ? new Date(currentUser.created_at).toLocaleDateString() : 'Unknown';

   return (
      <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
         <div className="absolute inset-0 bg-black/70 " onClick={onClose} />
         <div className="relative w-full max-w-md bg-white dark:bg-black p-0 border-4 border-black dark:border-white shadow-[8px_8px_0px_#000] dark:shadow-[8px_8px_0px_#fff] animate-scale-in overflow-hidden">
            {/* Header */}
            <div className="flex h-16 items-center justify-between px-4 border-b-4 border-black dark:border-white bg-emerald-500 z-20">
               <div className="flex items-center gap-2">
                  <UserIcon className="w-5 h-5 text-black" />
                  <h2 className="text-lg font-black text-black uppercase tracking-tighter">Profile</h2>
               </div>
               <button onClick={onClose} className="w-10 h-10 flex items-center justify-center hover:bg-black/10 transition-colors">
                  <X className="w-6 h-6 text-black" />
               </button>
            </div>

            <div className="p-8 flex flex-col items-center text-center">
               <div className="w-24 h-24 mb-6 border-4 border-black dark:border-white rounded-none shadow-[4px_4px_0px_#10b981]">
                  <Avatar src={`https://api.dicebear.com/7.x/avataaars/svg?seed=${currentUser.username}`} alt={currentUser.username} size="lg" status="online" />
               </div>
               <h3 className="text-3xl font-black text-black dark:text-white uppercase tracking-tighter mb-1">{currentUser.username}</h3>
               <p className="text-sm font-mono text-gray-600 dark:text-gray-400 mb-8">{currentUser.email}</p>

               <div className="w-full space-y-4 mb-8 text-left">
                  <div className="p-4 border-2 border-black dark:border-white bg-gray-50 dark:bg-gray-900 border-l-8 border-l-emerald-500 shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff]">
                     <p className="text-xs text-neutral-500 uppercase tracking-widest font-bold mb-1">Status</p>
                     <p className="font-medium text-black dark:text-white flex items-center gap-2">
                        <span className="w-3 h-3 bg-emerald-500 rounded-none border border-black dark:border-white block" /> Online
                     </p>
                  </div>
                  <div className="p-4 border-2 border-black dark:border-white bg-gray-50 dark:bg-gray-900 border-l-8 border-l-blue-500 shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff]">
                     <p className="text-xs text-neutral-500 uppercase tracking-widest font-bold mb-1">Joined</p>
                     <p className="font-medium text-black dark:text-white">{joinDate}</p>
                  </div>
               </div>

               <button onClick={() => { onClose(); onLogout(); }} className="w-full flex items-center justify-center py-4 bg-red-500 hover:bg-red-600 text-white border-4 border-black dark:border-white font-black uppercase tracking-widest shadow-[4px_4px_0px_#000] dark:shadow-[4px_4px_0px_#fff] active:translate-x-[4px] active:translate-y-[4px] active:shadow-none transition-all">
                  Sign Out
               </button>
            </div>
         </div>
      </div>
   );
};

// --- Settings Modal ---
interface SettingsModalProps {
   isOpen: boolean;
   onClose: () => void;
   theme: 'light' | 'dark';
   setTheme: (t: 'light' | 'dark') => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose, theme, setTheme }) => {
   if (!isOpen) return null;

   return (
      <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
         <div className="absolute inset-0 bg-black/70 " onClick={onClose} />
         <div className="relative w-full max-w-md bg-white dark:bg-black p-0 border-4 border-black dark:border-white shadow-[8px_8px_0px_#000] dark:shadow-[8px_8px_0px_#fff] animate-scale-in overflow-hidden">
            {/* Header */}
            <div className="flex h-16 items-center justify-between px-4 border-b-4 border-black dark:border-white bg-emerald-500 z-20">
               <div className="flex items-center gap-2">
                  <SettingsIcon className="w-5 h-5 text-black" />
                  <h2 className="text-lg font-black text-black uppercase tracking-tighter">Settings</h2>
               </div>
               <button onClick={onClose} className="w-10 h-10 flex items-center justify-center hover:bg-black/10 transition-colors">
                  <X className="w-6 h-6 text-black" />
               </button>
            </div>

            <div className="p-6 space-y-6 text-left">
               <h3 className="text-xs font-black text-black dark:text-white uppercase tracking-widest">Appearance</h3>

               <div className="grid grid-cols-2 gap-4">
                  <button onClick={() => setTheme('light')} className={`flex flex-col items-center p-4 border-4 transition-all ${theme === 'light' ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-900/20 shadow-[4px_4px_0px_#10b981]' : 'border-black dark:border-white bg-white dark:bg-black hover:bg-gray-50 dark:hover:bg-gray-900'}`}>
                     <Sun className={`w-8 h-8 mb-2 ${theme === 'light' ? 'text-emerald-500' : 'text-black dark:text-white'}`} />
                     <span className={`font-bold ${theme === 'light' ? 'text-emerald-600' : 'text-black dark:text-white'}`}>Light Mode</span>
                  </button>
                  <button onClick={() => setTheme('dark')} className={`flex flex-col items-center p-4 border-4 transition-all ${theme === 'dark' ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-900/20 shadow-[4px_4px_0px_#10b981]' : 'border-black dark:border-white bg-white dark:bg-black hover:bg-gray-50 dark:hover:bg-gray-900'}`}>
                     <Moon className={`w-8 h-8 mb-2 ${theme === 'dark' ? 'text-emerald-500' : 'text-black dark:text-white'}`} />
                     <span className={`font-bold ${theme === 'dark' ? 'text-emerald-600' : 'text-black dark:text-white'}`}>Dark Mode</span>
                  </button>
               </div>

               <div className="h-1 bg-black dark:bg-white w-full my-6 opacity-20" />

               <h3 className="text-xs font-black text-black dark:text-white uppercase tracking-widest">Security & Connectivity</h3>
               <div className="space-y-3">
                  <button className="w-full flex justify-between items-center p-4 border-2 border-black dark:border-white bg-gray-50 dark:bg-gray-900 hover:bg-emerald-500 hover:text-black group transition-colors shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff]">
                     <span className="font-bold text-black dark:text-white group-hover:text-black">Active Sessions</span>
                     <ChevronRight className="w-5 h-5 text-neutral-500 group-hover:text-black" />
                  </button>
                  <button className="w-full flex justify-between items-center p-4 border-2 border-black dark:border-white bg-gray-50 dark:bg-gray-900 hover:bg-emerald-500 hover:text-black group transition-colors shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff]">
                     <span className="font-bold text-black dark:text-white group-hover:text-black">Privacy Details</span>
                     <ChevronRight className="w-5 h-5 text-neutral-500 group-hover:text-black" />
                  </button>
               </div>
            </div>
         </div>
      </div>
   );
};
