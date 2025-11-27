import React, { useState, useRef, useEffect } from 'react';
import {
  Phone, Video, Search, MoreVertical, Smile, Paperclip, Mic, Send,
  Image as ImageIcon, FileText, X, Lock, Check, CheckCheck, ChevronLeft
} from 'lucide-react';
import Avatar from './Avatar';
import { Chat, Message, MessageType, User } from '../types';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useSocket } from '../context/SocketContext';

interface ChatWindowProps {
  chat: Chat | null;
  onSendMessage: (text: string, type?: MessageType) => void;
  onToggleRightSidebar: () => void;
  onBack?: () => void; // For mobile back button
}

const ChatWindow: React.FC<ChatWindowProps> = ({ chat, onSendMessage, onToggleRightSidebar, onBack }) => {
  const [inputText, setInputText] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [chat?.messages]);

  if (!chat) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center bg-gray-50/50 dark:bg-slate-900/50 backdrop-blur-sm p-8 text-center">
        <div className="w-64 h-64 bg-teal-100/20 dark:bg-teal-900/10 rounded-full flex items-center justify-center mb-8 relative">
          <div className="absolute inset-0 rounded-full border-2 border-teal-500/20 animate-pulse"></div>
          <Lock className="w-24 h-24 text-teal-500/50" />
        </div>
        <h2 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-teal-500 to-purple-600 mb-4">
          AGES Secure Messaging
        </h2>
        <p className="text-gray-500 dark:text-gray-400 max-w-md mx-auto mb-8">
          Select a conversation from the sidebar to start chatting securely with end-to-end encryption.
        </p>
      </div>
    );
  }

  const { socket } = useSocket(); // Import useSocket
  const { user } = useAuth(); // Import useAuth

  const handleSend = async () => {
    if (inputText.trim() && chat && user) {
      const text = inputText;
      setInputText(''); // Clear input immediately

      // Optimistic update
      onSendMessage(text, MessageType.TEXT);

      try {
        const recipientId = chat.participants[0].id;

        // 1. Prepare (encrypt) message via backend helper
        const prepareResponse = await api.post('/prepare_message', {
          recipient_id: recipientId,
          message: text
        });

        const { encrypted_message, signature, nonce, tag } = prepareResponse.data;

        // 2. Send via Socket.io
        socket?.emit('send_message', {
          recipient_id: recipientId,
          encrypted_message,
          signature,
          nonce,
          tag,
          client_msg_id: `m_${Date.now()}` // Simple client ID
        });

      } catch (error) {
        console.error('Failed to send message:', error);
        // TODO: Show error state for the message
        alert('Failed to send message securely. Encryption session might be missing.');
      }
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const participant = chat.participants[0];

  return (
    <div className="flex-1 flex flex-col h-full bg-white/50 dark:bg-slate-900/50 relative">
      {/* Header */}
      <div className="h-16 px-4 md:px-6 flex items-center justify-between bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border-b border-gray-200 dark:border-gray-800 z-10">
        <div className="flex items-center gap-3">
          {/* Mobile Back Button */}
          {onBack && (
            <button
              onClick={onBack}
              className="md:hidden p-2 rounded-full hover:bg-gray-100 dark:hover:bg-slate-800 text-gray-600 dark:text-gray-300 transition-colors"
              aria-label="Back to chats"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
          )}

          <div className="flex items-center cursor-pointer" onClick={onToggleRightSidebar}>
            <Avatar src={participant.avatar} alt={participant.name} status={participant.status as any} size="md" />
            <div className="ml-3">
              <h3 className="font-bold text-gray-900 dark:text-white">{participant.name}</h3>
              <div className="flex items-center text-xs text-gray-500">
                {participant.status === 'online' ? (
                  <span className="text-teal-500">Online</span>
                ) : (
                  <span>Last seen {participant.lastSeen}</span>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="hidden md:flex items-center px-3 py-1 rounded-full bg-green-100/50 dark:bg-green-900/20 border border-green-200 dark:border-green-800">
            <Lock className="w-3 h-3 text-green-600 dark:text-green-400 mr-1.5" />
            <span className="text-[10px] font-medium text-green-700 dark:text-green-300">Encrypted</span>
          </div>
          <button className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-slate-800 text-gray-600 dark:text-gray-300 transition-colors">
            <Search className="w-5 h-5" />
          </button>
          <button className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-slate-800 text-gray-600 dark:text-gray-300 transition-colors">
            <Phone className="w-5 h-5" />
          </button>
          <button className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-slate-800 text-gray-600 dark:text-gray-300 transition-colors">
            <Video className="w-5 h-5" />
          </button>
          <button
            className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-slate-800 text-gray-600 dark:text-gray-300 transition-colors"
            onClick={onToggleRightSidebar}
          >
            <MoreVertical className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-6 custom-scrollbar">
        {chat.messages.map((msg, index) => {
          const isMe = msg.senderId === user?.username;
          const showAvatar = !isMe && (index === 0 || chat.messages[index - 1].senderId !== msg.senderId);

          return (
            <div
              key={msg.id}
              className={`flex ${isMe ? 'justify-end' : 'justify-start'} group animate-fade-in`}
            >
              {!isMe && (
                <div className={`mr-2 flex-shrink-0 w-8 ${!showAvatar && 'opacity-0'}`}>
                  <Avatar src={participant.avatar} alt={participant.name} size="sm" showStatus={false} />
                </div>
              )}

              <div className={`max-w-[70%] relative ${isMe
                ? 'bg-gradient-to-br from-teal-500 to-teal-600 text-white rounded-[18px] rounded-tr-sm'
                : 'bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-100 rounded-[18px] rounded-tl-sm shadow-sm border border-gray-100 dark:border-gray-700'
                } p-3`}>

                {/* Message Content */}
                {msg.type === MessageType.TEXT && <p className="text-sm leading-relaxed whitespace-pre-wrap">{msg.content}</p>}

                {msg.type === MessageType.IMAGE && (
                  <div className="mb-1 overflow-hidden rounded-lg">
                    <img src={msg.mediaUrl} alt="Shared" className="max-w-full h-auto object-cover hover:scale-105 transition-transform duration-500" />
                    {msg.content && <p className="mt-2 text-sm">{msg.content}</p>}
                  </div>
                )}

                {msg.type === MessageType.FILE && (
                  <div className="flex items-center p-3 rounded-lg bg-black/10 dark:bg-white/10 backdrop-blur-sm">
                    <div className="p-2 bg-white/20 rounded-lg mr-3">
                      <FileText className="w-6 h-6" />
                    </div>
                    <div>
                      <p className="text-sm font-bold truncate">{msg.fileName}</p>
                      <p className="text-xs opacity-70">{msg.fileSize} • PDF</p>
                    </div>
                  </div>
                )}

                {/* Metadata */}
                <div className={`flex items-center justify-end mt-1 space-x-1 ${isMe ? 'text-teal-100' : 'text-gray-400'}`}>
                  <span className="text-[10px]">{msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  {isMe && (
                    <span className="ml-1">
                      {msg.status === 'read' ? <CheckCheck className="w-3 h-3" /> : <Check className="w-3 h-3" />}
                    </span>
                  )}
                </div>

                {/* Reactions */}
                {msg.reactions && msg.reactions.length > 0 && (
                  <div className={`absolute -bottom-3 ${isMe ? 'left-0' : 'right-0'} bg-white dark:bg-slate-700 rounded-full px-1.5 py-0.5 shadow-sm border border-gray-100 dark:border-gray-600 flex items-center space-x-1`}>
                    {msg.reactions.map((r, i) => (
                      <span key={i} className="text-xs">{r.emoji}</span>
                    ))}
                    <span className="text-[10px] text-gray-500 dark:text-gray-300 font-medium">{msg.reactions.reduce((acc, curr) => acc + curr.count, 0)}</span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <div className="p-4 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg border-t border-gray-200 dark:border-gray-800">
        <div className="flex items-end space-x-2 max-w-5xl mx-auto">
          <button className="p-3 rounded-full text-gray-500 hover:bg-gray-100 dark:hover:bg-slate-800 transition-colors">
            <Smile className="w-6 h-6" />
          </button>
          <button className="p-3 rounded-full text-gray-500 hover:bg-gray-100 dark:hover:bg-slate-800 transition-colors">
            <Paperclip className="w-6 h-6" />
          </button>

          <div className="flex-1 bg-gray-100 dark:bg-slate-800 rounded-[20px] px-4 py-2 focus-within:ring-2 focus-within:ring-teal-500/50 transition-all border border-transparent focus-within:border-teal-500/30">
            <textarea
              id="message-input"
              aria-label="Type a message"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Type a message..."
              rows={1}
              className="w-full bg-transparent border-none focus:ring-0 resize-none max-h-32 text-gray-900 dark:text-white placeholder-gray-500 py-2 custom-scrollbar"
              style={{ minHeight: '24px' }}
            />
          </div>

          {inputText.trim() ? (
            <button
              onClick={handleSend}
              className="p-3 rounded-full bg-teal-500 text-white shadow-lg shadow-teal-500/30 hover:scale-105 hover:bg-teal-600 transition-all animate-fade-in"
            >
              <Send className="w-5 h-5 ml-0.5" />
            </button>
          ) : (
            <button className="p-3 rounded-full text-gray-500 hover:bg-gray-100 dark:hover:bg-slate-800 transition-colors">
              <Mic className="w-6 h-6" />
            </button>
          )}
        </div>
        <div className="text-center mt-2">
          <p className="text-[10px] text-gray-400 flex items-center justify-center gap-1">
            <Lock className="w-2.5 h-2.5" /> End-to-end encrypted
          </p>
        </div>
      </div>
    </div>
  );
};

export default ChatWindow;