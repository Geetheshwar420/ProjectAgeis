import React, { useState, useEffect, useRef } from 'react';
import {
   X, UserPlus, Copy, Share2, Mail, Link as LinkIcon, Check,
   Search, Clock, ChevronRight, User, Users, Calendar, ArrowRight,
   MessageSquare, MoreHorizontal, Shield, Smartphone
} from 'lucide-react';
import Avatar from './Avatar';
import { User as UserType } from '../types';
import api from '../services/api';

// --- Add Friend Modal ---

interface AddFriendModalProps {
   isOpen: boolean;
   onClose: () => void;
   onAdd: (username: string) => void;
}

export const AddFriendModal: React.FC<AddFriendModalProps> = ({ isOpen, onClose, onAdd }) => {
   const [searchQuery, setSearchQuery] = useState('');
   const [isSearching, setIsSearching] = useState(false);
   const [searchResults, setSearchResults] = useState<any[]>([]);
   const [hasSearched, setHasSearched] = useState(false);
   const [recentSearches, setRecentSearches] = useState<{ username: string, time: string }[]>([]);
   const [friendRequestsSent, setFriendRequestsSent] = useState<Set<string>>(new Set());

   // Debounced Search with real API
   useEffect(() => {
      const timer = setTimeout(async () => {
         if (searchQuery.length >= 2) {
            setIsSearching(true);
            try {
               const response = await api.get('/users');
               const results = response.data.filter((user: any) =>
                  user.username.toLowerCase().includes(searchQuery.toLowerCase())
               );
               setSearchResults(results);
               setHasSearched(true);
            } catch (error) {
               console.error('Failed to search users:', error);
               setSearchResults([]);
            } finally {
               setIsSearching(false);
            }
         } else {
            setSearchResults([]);
            setHasSearched(false);
            setIsSearching(false);
         }
      }, 400);

      return () => clearTimeout(timer);
   }, [searchQuery]);

   if (!isOpen) return null;

   const handleSendRequest = (userId: string, username: string) => {
      // Simulate API call
      setFriendRequestsSent(prev => new Set(prev).add(userId));
      onAdd(username);

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
         <div className="absolute inset-0 bg-black/60 backdrop-blur-sm transition-opacity" onClick={onClose} />

         <div className="relative w-full h-full md:h-auto md:max-h-[700px] md:w-[600px] bg-white dark:bg-slate-900 md:rounded-2xl shadow-2xl flex flex-col overflow-hidden animate-scale-in">

            {/* Header (Sticky) */}
            <div className="flex-shrink-0 h-16 flex items-center justify-between px-4 border-b border-gray-100 dark:border-gray-800 bg-white/80 dark:bg-slate-900/80 backdrop-blur-md z-20">
               <div className="w-10"></div> {/* Spacer */}
               <div className="flex flex-col items-center">
                  <div className="flex items-center gap-2">
                     <UserPlus className="w-5 h-5 text-teal-500" />
                     <h2 className="text-lg font-bold text-gray-900 dark:text-white">Add New Friend</h2>
                  </div>
               </div>
               <button
                  onClick={onClose}
                  className="w-10 h-10 flex items-center justify-center rounded-full hover:bg-gray-100 dark:hover:bg-slate-800 transition-colors"
               >
                  <X className="w-6 h-6 text-gray-500" />
               </button>
            </div>

            {/* Search Input Area */}
            <div className="flex-shrink-0 p-5 bg-white dark:bg-slate-900 z-10">
               <div className={`relative flex items-center transition-all duration-200 rounded-2xl border-2 ${isSearching || searchQuery ? 'border-teal-500 bg-white dark:bg-slate-800' : 'border-transparent bg-gray-100 dark:bg-slate-800'}`}>
                  <div className="absolute left-4 flex items-center pointer-events-none">
                     {isSearching ? (
                        <div className="w-5 h-5 border-2 border-teal-500/30 border-t-teal-500 rounded-full animate-spin" />
                     ) : (
                        <Search className={`w-5 h-5 ${searchQuery ? 'text-teal-500' : 'text-gray-400'}`} />
                     )}
                     <span className="ml-2 text-gray-400 font-medium">@</span>
                  </div>
                  <input
                     id="friend-search-input"
                     aria-label="Search for friends by username"
                     type="text"
                     value={searchQuery}
                     onChange={(e) => setSearchQuery(e.target.value.replace(/\s/g, ''))} // No spaces
                     placeholder="username"
                     className="w-full py-3.5 pl-12 pr-10 bg-transparent border-none focus:ring-0 text-gray-900 dark:text-white placeholder-gray-400 text-base"
                     autoFocus
                  />
                  {searchQuery && (
                     <button
                        onClick={() => setSearchQuery('')}
                        className="absolute right-3 p-1 rounded-full text-gray-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/10 transition-colors"
                     >
                        <X className="w-4 h-4" />
                     </button>
                  )}
               </div>
            </div>

            {/* Tab Navigation (only if no search query) */}
            {!searchQuery && (
               <div className="flex px-5 border-b border-gray-100 dark:border-gray-800">
                  <div className="flex-1 pb-3 text-sm font-medium text-teal-600 dark:text-teal-400 relative">
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
                        <div key={i} className="flex items-center p-4 rounded-2xl bg-gray-50 dark:bg-slate-800/50 animate-pulse">
                           <div className="w-14 h-14 rounded-full bg-gray-200 dark:bg-slate-700" />
                           <div className="ml-4 flex-1">
                              <div className="h-4 w-32 bg-gray-200 dark:bg-slate-700 rounded mb-2" />
                              <div className="h-3 w-24 bg-gray-200 dark:bg-slate-700 rounded" />
                           </div>
                        </div>
                     ))}
                  </div>
               )}

               {/* Case 2: Search Results Found */}
               {!isSearching && searchQuery && searchResults.length > 0 && (
                  <div className="space-y-3 animate-fade-in">
                     <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Search Results</h3>
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
                        <div className="w-24 h-24 bg-gray-100 dark:bg-slate-800 rounded-full flex items-center justify-center animate-bounce-soft">
                           <Search className="w-10 h-10 text-gray-400" />
                        </div>
                        <div className="absolute -top-1 -right-1 w-8 h-8 bg-teal-100 dark:bg-teal-900/50 rounded-full flex items-center justify-center border-4 border-white dark:border-slate-900">
                           <div className="text-teal-600 dark:text-teal-400 font-bold text-lg">?</div>
                        </div>
                     </div>

                     <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">No users found</h3>
                     <p className="text-gray-500 text-center max-w-xs mb-8">
                        We couldn't find anyone with the username <span className="text-teal-500 font-mono">@{searchQuery}</span>
                     </p>

                     {/* Invite Card */}
                     <div className="w-full bg-gradient-to-br from-teal-50 to-purple-50 dark:from-teal-900/20 dark:to-purple-900/20 border border-teal-100 dark:border-teal-800/30 rounded-2xl p-6 relative overflow-hidden group">
                        <div className="absolute top-0 right-0 w-32 h-32 bg-teal-500/10 rounded-full blur-3xl -mr-16 -mt-16 transition-all group-hover:bg-teal-500/20" />

                        <div className="flex items-center gap-4 mb-4">
                           <div className="w-12 h-12 bg-white dark:bg-slate-800 rounded-xl flex items-center justify-center shadow-sm">
                              <Share2 className="w-6 h-6 text-teal-600 dark:text-teal-400" />
                           </div>
                           <div>
                              <h4 className="font-bold text-gray-900 dark:text-white">Invite to AGES</h4>
                              <p className="text-xs text-gray-500">Send them an invite link</p>
                           </div>
                        </div>

                        <div className="bg-white dark:bg-slate-800 rounded-xl border border-gray-200 dark:border-gray-700 flex items-center justify-between p-1 pl-4 mb-4">
                           <span className="text-sm text-gray-500 font-mono truncate mr-2">
                              ages.app/invite/{searchQuery}
                           </span>
                           <button className="p-2 bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 rounded-lg transition-colors">
                              <Copy className="w-4 h-4 text-gray-600 dark:text-gray-300" />
                           </button>
                        </div>

                        <div className="flex gap-2 justify-center">
                           <button className="flex-1 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2">
                              <MessageSquare className="w-4 h-4" /> WhatsApp
                           </button>
                           <button className="flex-1 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2">
                              <Mail className="w-4 h-4" /> Email
                           </button>
                        </div>
                     </div>

                     <div className="mt-8 w-full">
                        <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">Suggestions</h4>
                        <ul className="text-sm text-gray-500 space-y-2">
                           <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 bg-gray-300 rounded-full" /> Check spelling of the username</li>
                           <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 bg-gray-300 rounded-full" /> Ask them to share their QR code</li>
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
                              <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wider">Recent</h3>
                              <button onClick={clearRecent} className="text-xs text-teal-600 hover:text-teal-700">Clear All</button>
                           </div>
                           <div className="space-y-1">
                              {recentSearches.map((item, idx) => (
                                 <div key={idx} className="group flex items-center justify-between p-3 hover:bg-gray-50 dark:hover:bg-slate-800 rounded-xl transition-colors cursor-pointer" onClick={() => setSearchQuery(item.username.replace('@', ''))}>
                                    <div className="flex items-center gap-3">
                                       <div className="w-10 h-10 rounded-full bg-gray-100 dark:bg-slate-800 flex items-center justify-center">
                                          <Clock className="w-5 h-5 text-gray-400" />
                                       </div>
                                       <div>
                                          <p className="font-medium text-gray-900 dark:text-white">{item.username}</p>
                                          <p className="text-xs text-gray-500">{item.time}</p>
                                       </div>
                                    </div>
                                    <button
                                       onClick={(e) => { e.stopPropagation(); removeRecent(item.username); }}
                                       className="p-2 opacity-0 group-hover:opacity-100 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-full text-gray-400 hover:text-red-500 transition-all"
                                    >
                                       <X className="w-4 h-4" />
                                    </button>
                                 </div>
                              ))}
                           </div>
                        </>
                     ) : (
                        <div className="flex flex-col items-center justify-center py-12 text-gray-400">
                           <Clock className="w-12 h-12 mb-4 opacity-20" />
                           <p>No recent searches</p>
                        </div>
                     )}
                  </div>
               )}

            </div>

            {/* Footer */}
            <div className="p-4 border-t border-gray-100 dark:border-gray-800 bg-gray-50 dark:bg-slate-900/50 flex justify-center">
               <p className="text-xs text-gray-400 flex items-center gap-1">
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
      <div className="group relative flex items-center p-4 rounded-2xl bg-white dark:bg-slate-800 border border-transparent hover:border-teal-500/30 hover:shadow-xl hover:shadow-teal-500/5 transition-all duration-300">
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
               <h4 className="text-sm font-bold text-gray-900 dark:text-white truncate">{user.username}</h4>
               <span className="text-xs text-gray-500 truncate">{user.email}</span>
            </div>

            <div className="flex items-center gap-3 mt-1 text-xs text-gray-500">
               <span className="flex items-center">
                  <Calendar className="w-3 h-3 mr-1" /> User on platform
               </span>
            </div>
         </div>

         <div className="ml-4">
            {isRequestSent ? (
               <button disabled className="flex items-center px-4 py-2 bg-gray-100 dark:bg-slate-700 text-gray-500 rounded-xl text-sm font-medium cursor-default">
                  <Check className="w-4 h-4 mr-1.5" /> Sent
               </button>
            ) : (
               <button
                  onClick={onSendRequest}
                  className="flex items-center px-4 py-2 bg-gradient-to-r from-teal-500 to-teal-600 hover:from-teal-600 hover:to-teal-700 text-white rounded-xl text-sm font-medium shadow-lg shadow-teal-500/20 transform active:scale-95 transition-all"
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
         <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />

         <div className="relative w-full max-w-md bg-white dark:bg-slate-900 rounded-3xl shadow-2xl p-0 border border-white/10 animate-scale-in overflow-hidden">
            {/* Header */}
            <div className="relative h-32 bg-gradient-to-br from-purple-600 to-indigo-600 p-6 flex flex-col items-center justify-center text-center">
               <button onClick={onClose} className="absolute top-4 right-4 p-2 bg-black/20 hover:bg-black/30 rounded-full text-white transition-colors">
                  <X className="w-4 h-4" />
               </button>
               <div className="w-16 h-16 bg-white rounded-2xl shadow-xl flex items-center justify-center transform translate-y-8 rotate-3">
                  <Share2 className="w-8 h-8 text-purple-600" />
               </div>
            </div>

            <div className="pt-12 pb-8 px-6 text-center">
               <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">Invite Friends</h2>
               <p className="text-gray-500 text-sm mb-8">Share this link to connect securely on AGES.</p>

               {/* Link Box */}
               <div className="bg-gray-50 dark:bg-slate-800 p-2 rounded-2xl border border-gray-200 dark:border-gray-700 flex items-center justify-between gap-2 mb-8 shadow-inner">
                  <div className="flex-1 px-3 py-2 overflow-hidden">
                     <p className="text-xs text-gray-400 font-semibold uppercase tracking-wider mb-0.5">Your Invite Link</p>
                     <p className="text-sm font-mono text-gray-800 dark:text-gray-200 truncate">{inviteLink}</p>
                  </div>
                  <button
                     onClick={handleCopy}
                     className={`p-3 rounded-xl transition-all duration-300 ${copied ? 'bg-green-500 text-white' : 'bg-white dark:bg-slate-700 text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-slate-600 shadow-sm'}`}
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
      <div className={`w-12 h-12 rounded-2xl ${color} text-white flex items-center justify-center shadow-lg transform transition-transform group-hover:scale-110 group-active:scale-95`}>
         {icon}
      </div>
      <span className="text-xs font-medium text-gray-600 dark:text-gray-400">{label}</span>
   </button>
);
