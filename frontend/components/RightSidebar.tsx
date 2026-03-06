import React from 'react';
import {
  X, Bell, Image as ImageIcon, File as FileIcon, Link as LinkIcon, Lock as LockIcon,
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
  const participant = chat.participants && chat.participants.length > 0
    ? chat.participants[0]
    : { id: 'unknown', name: 'Unknown User', avatar: '', status: 'offline', lastSeen: 'never', bio: 'No data available', username: 'unknown' };

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
    <div className={`w-[360px] h-full bg-slate-50 dark:bg-black font-sans selection:bg-emerald-500 selection:text-black border-l-4 border-black dark:border-white flex flex-col transition-transform duration-300 absolute right-0 top-0 bottom-0 z-20`}>
      {/* Header */}
      <div className="h-20 px-6 flex items-center justify-between border-b-4 border-black dark:border-white bg-white dark:bg-black shadow-[0px_4px_0px_#10b981] z-10">
        <h3 className="font-black text-xl text-black dark:text-white uppercase tracking-tighter">TARGET_INFO</h3>
        <button onClick={onClose} className="p-2 border-2 border-black dark:border-white bg-white dark:bg-black text-black dark:text-white shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] hover:bg-emerald-500 hover:text-black hover:translate-x-[1px] hover:translate-y-[1px] hover:shadow-[1px_1px_0px_#000] active:translate-x-[2px] active:translate-y-[2px] active:shadow-none transition-all">
          <X className="w-5 h-5" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-8 relative">
        {/* Stark Background Pattern */}
        <div className="absolute inset-0 pointer-events-none z-0 opacity-[0.03] dark:opacity-[0.05]"
          style={{ backgroundImage: 'linear-gradient(to right, #000 1px, transparent 1px), linear-gradient(to bottom, #000 1px, transparent 1px)', backgroundSize: '40px 40px' }} />

        {/* Profile */}
        <div className="flex flex-col items-center relative z-10 border-b-4 border-black dark:border-white pb-6 pt-4">
          <div className="border-4 border-black dark:border-white bg-white shadow-[4px_4px_0px_#000] dark:shadow-[4px_4px_0px_#fff] mb-6">
            <Avatar src={participant.avatar} alt={participant.name} size="xl" status={participant.status as any} />
          </div>
          <h2 className="text-2xl font-black text-black dark:text-white uppercase tracking-tight">{participant.name}</h2>
          <span className="font-mono text-[10px] font-bold tracking-widest uppercase text-emerald-500 bg-black dark:bg-white dark:text-black px-2 py-1 mt-2 border-2 border-black dark:border-white">
            ID: {participant.username}
          </span>
          <p className="text-xs font-mono uppercase text-black/70 dark:text-white/70 text-center mt-4 tracking-wider max-w-[280px]">
            {participant.bio}
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex gap-4 justify-center border-b-4 border-black dark:border-white pb-8 relative z-10">
          <div className="flex flex-col items-center gap-2 cursor-pointer group">
            <div className="w-12 h-12 border-2 border-black dark:border-white bg-white dark:bg-black shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] flex items-center justify-center group-hover:bg-emerald-500 group-hover:text-black transition-all group-hover:translate-x-[1px] group-hover:translate-y-[1px] group-hover:shadow-[1px_1px_0px_#000] active:translate-x-[2px] active:translate-y-[2px] active:shadow-none">
              <Bell className="w-5 h-5 text-black dark:text-white group-hover:text-black" />
            </div>
            <span className="font-mono text-[10px] font-bold uppercase text-black dark:text-white tracking-widest">Mute</span>
          </div>
          <div className="flex flex-col items-center gap-2 cursor-pointer group">
            <div className="w-12 h-12 border-2 border-black dark:border-white bg-white dark:bg-black shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] flex items-center justify-center group-hover:bg-emerald-500 group-hover:text-black transition-all group-hover:translate-x-[1px] group-hover:translate-y-[1px] group-hover:shadow-[1px_1px_0px_#000] active:translate-x-[2px] active:translate-y-[2px] active:shadow-none">
              <Search className="w-5 h-5 text-black dark:text-white group-hover:text-black" />
            </div>
            <span className="font-mono text-[10px] font-bold uppercase text-black dark:text-white tracking-widest">Search</span>
          </div>
          <div className="flex flex-col items-center gap-2 cursor-pointer group">
            <div className="w-12 h-12 border-2 border-black dark:border-white bg-white dark:bg-black shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] flex items-center justify-center group-hover:bg-emerald-500 group-hover:text-black transition-all group-hover:translate-x-[1px] group-hover:translate-y-[1px] group-hover:shadow-[1px_1px_0px_#000] active:translate-x-[2px] active:translate-y-[2px] active:shadow-none">
              <Clock className="w-5 h-5 text-black dark:text-white group-hover:text-black" />
            </div>
            <span className="font-mono text-[10px] font-bold uppercase text-black dark:text-white tracking-widest">Logs</span>
          </div>
        </div>

        {/* Encryption Status */}
        <div className="bg-emerald-500 p-5 border-4 border-black dark:border-white shadow-[6px_6px_0px_#000] dark:shadow-[6px_6px_0px_#fff] relative z-10 transition-transform hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[4px_4px_0px_#000] dark:hover:shadow-[4px_4px_0px_#fff]">
          <div className="flex items-center justify-between mb-4 border-b-2 border-black pb-2">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-black" />
              <h4 className="font-black text-black text-sm uppercase tracking-widest">VERIFIED_LINK</h4>
            </div>
            <LockIcon className="w-4 h-4 text-black" />
          </div>
          <EncryptionVisualizer />
          <p className="font-mono text-[10px] font-bold text-black/80 mt-4 uppercase tracking-wider leading-relaxed bg-white/20 p-2 border border-black/20">
            DATA STREAM IS FULLY ENCRYPTED. AES-256-GCM ACTIVE.
          </p>
        </div>

        {/* Activity Stats */}
        <div className="relative z-10">
          <h4 className="font-mono text-[10px] font-black uppercase tracking-widest mb-3 text-black dark:text-white border-b-2 border-black dark:border-white pb-2 flex items-center gap-2">
            <span className="w-2 h-2 bg-emerald-500 inline-block border border-black dark:border-white"></span>
            PING_ACTIVITY_LOG
          </h4>
          <div className="h-32 w-full border-2 border-black dark:border-white bg-white dark:bg-black p-2 shadow-[4px_4px_0px_#000] dark:shadow-[4px_4px_0px_#fff]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 5, right: 0, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorMsgs" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <Tooltip
                  contentStyle={{ backgroundColor: '#000', border: '2px solid #fff', borderRadius: '0px', fontSize: '12px', fontFamily: 'monospace', color: '#10b981' }}
                  itemStyle={{ color: '#10b981', fontWeight: 'bold' }}
                  labelStyle={{ color: '#fff' }}
                  cursor={{ stroke: '#10b981', strokeWidth: 2, strokeDasharray: '3 3' }}
                />
                <Area type="monotone" dataKey="msgs" stroke="#000" fillOpacity={1} fill="url(#colorMsgs)" strokeWidth={3} activeDot={{ r: 6, fill: '#10b981', stroke: '#000', strokeWidth: 2 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Media Links Docs */}
        <div className="relative z-10 space-y-3 pb-4">
          <div className="flex items-center justify-between p-3 border-2 border-black dark:border-white bg-white dark:bg-black shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] cursor-pointer hover:bg-emerald-500 hover:text-black transition-all group hover:translate-x-[1px] hover:translate-y-[1px] hover:shadow-[1px_1px_0px_#000]">
            <div className="flex items-center gap-3">
              <ImageIcon className="w-5 h-5 text-black dark:text-white group-hover:text-black" />
              <span className="font-mono text-xs font-bold uppercase tracking-widest text-black dark:text-white group-hover:text-black">MEDIA_ASSETS</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] font-bold bg-black dark:bg-white text-white dark:text-black px-1.5 py-0.5 group-hover:bg-black group-hover:text-emerald-500">124</span>
              <ChevronRight className="w-4 h-4 text-black dark:text-white group-hover:text-black" />
            </div>
          </div>

          <div className="flex items-center justify-between p-3 border-2 border-black dark:border-white bg-white dark:bg-black shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] cursor-pointer hover:bg-emerald-500 hover:text-black transition-all group hover:translate-x-[1px] hover:translate-y-[1px] hover:shadow-[1px_1px_0px_#000]">
            <div className="flex items-center gap-3">
              <FileIcon className="w-5 h-5 text-black dark:text-white group-hover:text-black" />
              <span className="font-mono text-xs font-bold uppercase tracking-widest text-black dark:text-white group-hover:text-black">DOCUMENTS</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] font-bold bg-black dark:bg-white text-white dark:text-black px-1.5 py-0.5 group-hover:bg-black group-hover:text-emerald-500">32</span>
              <ChevronRight className="w-4 h-4 text-black dark:text-white group-hover:text-black" />
            </div>
          </div>

          <div className="flex items-center justify-between p-3 border-2 border-black dark:border-white bg-white dark:bg-black shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] cursor-pointer hover:bg-emerald-500 hover:text-black transition-all group hover:translate-x-[1px] hover:translate-y-[1px] hover:shadow-[1px_1px_0px_#000]">
            <div className="flex items-center gap-3">
              <LinkIcon className="w-5 h-5 text-black dark:text-white group-hover:text-black" />
              <span className="font-mono text-xs font-bold uppercase tracking-widest text-black dark:text-white group-hover:text-black">EXTERNAL_LINKS</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] font-bold bg-black dark:bg-white text-white dark:text-black px-1.5 py-0.5 group-hover:bg-black group-hover:text-emerald-500">8</span>
              <ChevronRight className="w-4 h-4 text-black dark:text-white group-hover:text-black" />
            </div>
          </div>
        </div>

        {/* Danger Zone */}
        <div className="space-y-4 pt-6 mt-4 border-t-4 border-black dark:border-white relative z-10 pb-4">
          <button className="w-full flex items-center justify-center gap-3 p-3 border-4 border-black dark:border-white bg-red-500 text-black shadow-[4px_4px_0px_#000] dark:shadow-[4px_4px_0px_#fff] font-black uppercase tracking-widest hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0px_#000] dark:hover:shadow-[2px_2px_0px_#fff] hover:bg-black hover:text-red-500 dark:hover:bg-white active:shadow-none active:translate-x-[4px] active:translate-y-[4px] transition-all">
            <Ban className="w-5 h-5" />
            TERMINATE_USER
          </button>
          <button className="w-full flex items-center justify-center gap-3 p-3 border-4 border-black dark:border-white bg-transparent text-red-600 dark:text-red-400 shadow-[4px_4px_0px_#000] dark:shadow-[4px_4px_0px_#fff] font-black uppercase tracking-widest hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0px_#000] dark:hover:shadow-[2px_2px_0px_#fff] hover:bg-red-500 hover:text-black dark:hover:text-black active:shadow-none active:translate-x-[4px] active:translate-y-[4px] transition-all">
            <Trash2 className="w-5 h-5" />
            WIPE_LOGS
          </button>
        </div>

      </div>
    </div>
  );
};

export default RightSidebar;