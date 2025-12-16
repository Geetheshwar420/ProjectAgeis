import React from 'react';
import { 
  X, Bell, Image as ImageIcon, File, Link as LinkIcon, 
  ChevronRight, Shield, Clock, Trash2, Ban, Search
} from 'lucide-react';
import { Chat } from '../types';
import Avatar from './Avatar';
import EncryptionVisualizer from './EncryptionVisualizer';
import { AreaChart, Area, XAxis, Tooltip, ResponsiveContainer } from 'recharts';

interface RightSidebarProps {
  chat: Chat | null;
  isOpen: boolean;
  onClose: () => void;
}

const RightSidebar: React.FC<RightSidebarProps> = ({ chat, isOpen, onClose }) => {
  if (!chat || !isOpen) return null;
  const participant = chat.participants[0];

  const chartData = [
    { day: 'Mon', msgs: 24 },
    { day: 'Tue', msgs: 45 },
    { day: 'Wed', msgs: 12 },
    { day: 'Thu', msgs: 56 },
    { day: 'Fri', msgs: 33 },
    { day: 'Sat', msgs: 18 },
    { day: 'Sun', msgs: 9 },
  ];

  return (
    <div className={`w-[360px] h-full bg-white/90 dark:bg-slate-900/90 backdrop-blur-xl border-l border-gray-200 dark:border-gray-800 flex flex-col transition-transform duration-300 absolute right-0 top-0 bottom-0 z-20 shadow-2xl`}>
      {/* Header */}
      <div className="h-16 px-4 flex items-center justify-between border-b border-gray-100 dark:border-gray-800">
        <h3 className="font-semibold text-lg text-gray-800 dark:text-white">Contact Info</h3>
        <button onClick={onClose} className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-slate-800 transition-colors">
          <X className="w-5 h-5 text-gray-500" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-6">
        {/* Profile */}
        <div className="flex flex-col items-center">
          <Avatar src={participant.avatar} alt={participant.name} size="xl" status={participant.status as any} className="mb-4" />
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">{participant.name}</h2>
          <p className="text-sm text-teal-600 dark:text-teal-400 font-medium">{participant.username}</p>
          <p className="text-sm text-gray-500 text-center mt-2">{participant.bio}</p>
        </div>

        {/* Action Buttons */}
        <div className="flex gap-4 justify-center border-b border-gray-100 dark:border-gray-800 pb-6">
           <div className="flex flex-col items-center gap-1 cursor-pointer group">
              <div className="w-10 h-10 rounded-full bg-gray-100 dark:bg-slate-800 flex items-center justify-center group-hover:bg-teal-100 dark:group-hover:bg-teal-900/30 transition-colors">
                <Bell className="w-5 h-5 text-gray-600 dark:text-gray-300 group-hover:text-teal-600" />
              </div>
              <span className="text-xs text-gray-500">Mute</span>
           </div>
           <div className="flex flex-col items-center gap-1 cursor-pointer group">
              <div className="w-10 h-10 rounded-full bg-gray-100 dark:bg-slate-800 flex items-center justify-center group-hover:bg-teal-100 dark:group-hover:bg-teal-900/30 transition-colors">
                <Search className="w-5 h-5 text-gray-600 dark:text-gray-300 group-hover:text-teal-600" />
              </div>
              <span className="text-xs text-gray-500">Search</span>
           </div>
           <div className="flex flex-col items-center gap-1 cursor-pointer group">
              <div className="w-10 h-10 rounded-full bg-gray-100 dark:bg-slate-800 flex items-center justify-center group-hover:bg-teal-100 dark:group-hover:bg-teal-900/30 transition-colors">
                <Clock className="w-5 h-5 text-gray-600 dark:text-gray-300 group-hover:text-teal-600" />
              </div>
              <span className="text-xs text-gray-500">History</span>
           </div>
        </div>

        {/* Encryption Status */}
        <div className="bg-gradient-to-br from-green-50 to-emerald-50 dark:from-green-900/10 dark:to-emerald-900/10 rounded-xl p-4 border border-green-100 dark:border-green-800/30">
          <div className="flex items-center gap-2 mb-3">
             <Shield className="w-5 h-5 text-green-600" />
             <h4 className="font-semibold text-green-800 dark:text-green-400 text-sm">Encryption Verified</h4>
          </div>
          <EncryptionVisualizer />
          <p className="text-xs text-green-700/70 dark:text-green-400/70 mt-3">
             Messages are end-to-end encrypted. No one outside of this chat, not even AGES, can read or listen to them.
          </p>
        </div>

        {/* Activity Stats */}
        <div>
          <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Activity</h4>
          <div className="h-32 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="colorMsgs" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#21808D" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#21808D" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1A1A1A', border: 'none', borderRadius: '8px', fontSize: '12px' }}
                  itemStyle={{ color: '#fff' }}
                />
                <Area type="monotone" dataKey="msgs" stroke="#21808D" fillOpacity={1} fill="url(#colorMsgs)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Media Links Docs */}
        <div>
           <div className="flex items-center justify-between py-3 hover:bg-gray-50 dark:hover:bg-slate-800/50 rounded-lg px-2 cursor-pointer transition-colors">
              <div className="flex items-center gap-3">
                 <ImageIcon className="w-5 h-5 text-gray-400" />
                 <span className="text-sm font-medium text-gray-700 dark:text-gray-200">Media</span>
              </div>
              <div className="flex items-center gap-1">
                 <span className="text-xs text-gray-400">124</span>
                 <ChevronRight className="w-4 h-4 text-gray-400" />
              </div>
           </div>
           <div className="flex items-center justify-between py-3 hover:bg-gray-50 dark:hover:bg-slate-800/50 rounded-lg px-2 cursor-pointer transition-colors">
              <div className="flex items-center gap-3">
                 <File className="w-5 h-5 text-gray-400" />
                 <span className="text-sm font-medium text-gray-700 dark:text-gray-200">Files</span>
              </div>
              <div className="flex items-center gap-1">
                 <span className="text-xs text-gray-400">32</span>
                 <ChevronRight className="w-4 h-4 text-gray-400" />
              </div>
           </div>
           <div className="flex items-center justify-between py-3 hover:bg-gray-50 dark:hover:bg-slate-800/50 rounded-lg px-2 cursor-pointer transition-colors">
              <div className="flex items-center gap-3">
                 <LinkIcon className="w-5 h-5 text-gray-400" />
                 <span className="text-sm font-medium text-gray-700 dark:text-gray-200">Links</span>
              </div>
              <div className="flex items-center gap-1">
                 <span className="text-xs text-gray-400">8</span>
                 <ChevronRight className="w-4 h-4 text-gray-400" />
              </div>
           </div>
        </div>

        {/* Danger Zone */}
        <div className="space-y-2 pt-4 border-t border-gray-100 dark:border-gray-800">
           <button className="w-full flex items-center gap-3 p-3 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/10 rounded-lg transition-colors text-sm font-medium">
             <Ban className="w-5 h-5" />
             Block User
           </button>
           <button className="w-full flex items-center gap-3 p-3 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/10 rounded-lg transition-colors text-sm font-medium">
             <Trash2 className="w-5 h-5" />
             Delete Chat
           </button>
        </div>

      </div>
    </div>
  );
};

export default RightSidebar;