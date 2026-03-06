import React, { useState, useRef, useEffect } from 'react';
import {
  Search, MoreVertical, Smile, Paperclip, Send,
  Image as ImageIcon, FileText, X, Lock as LockIcon, Check, CheckCheck, ChevronLeft
} from 'lucide-react';
import Avatar from './Avatar';
import { Chat, Message, MessageType, User } from '../types';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useSocket } from '../context/SocketContext';
import { CryptoService } from '../services/CryptoEngine';
import { FileService } from '../services/FileService';
import { StorageService } from '../services/StorageService';

interface ChatWindowProps {
  chat: Chat | null;
  onSendMessage: (text: string, type?: MessageType) => void;
  onToggleRightSidebar: () => void;
  onBack?: () => void; // For mobile back button
}

const ChatWindow: React.FC<ChatWindowProps> = ({ chat, onSendMessage, onToggleRightSidebar, onBack }) => {
  const [inputText, setInputText] = useState('');
  const [showEmojiPicker, setShowEmojiPicker] = useState(false);
  const [isUploading, setIsUploading] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const { socket } = useSocket();
  const { user } = useAuth();

  const participant = chat?.participants && chat.participants.length > 0
    ? chat.participants[0]
    : { id: 'unknown', name: 'Unknown User', avatar: '', status: 'offline', lastSeen: 'never' };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    const loadLocalHistory = async () => {
      if (chat?.id && participant.id !== 'unknown') {
        try {
          const localMsgs = await StorageService.getMessages(participant.id);
          console.log('Loaded local history:', localMsgs);
        } catch (err) {
          console.error('Failed to load local history:', err);
        }
      }
    };
    loadLocalHistory();
    scrollToBottom();
  }, [chat?.id, participant.id]);

  if (!chat) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center bg-white dark:bg-black font-sans selection:bg-emerald-500 selection:text-black p-8 text-center relative overflow-hidden">
        {/* Stark Background Pattern */}
        <div className="absolute inset-0 pointer-events-none z-0 opacity-[0.03] dark:opacity-[0.05]"
          style={{ backgroundImage: 'linear-gradient(to right, #000 1px, transparent 1px), linear-gradient(to bottom, #000 1px, transparent 1px)', backgroundSize: '40px 40px' }} />

        <div className="w-32 h-32 bg-emerald-500 border-4 border-black dark:border-white shadow-[8px_8px_0px_#000] dark:shadow-[8px_8px_0px_#fff] flex items-center justify-center mb-8 relative z-10 transition-transform hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[6px_6px_0px_#000] dark:hover:shadow-[6px_6px_0px_#fff]">
          <LockIcon className="w-16 h-16 text-black" />
        </div>
        <h2 className="text-4xl font-black text-black dark:text-white uppercase tracking-tighter mb-4 z-10">
          SECURE_TERMINAL
        </h2>
        <p className="font-mono text-sm font-bold text-black/70 dark:text-white/70 max-w-md mx-auto mb-8 uppercase tracking-widest z-10 border-2 border-black dark:border-white p-4 bg-white/50 dark:bg-black/50 backdrop-blur-sm">
          AWAITING CONNECTION. SELECT A NODE TO INITIALIZE END-TO-END ENCRYPTED SESSION.
        </p>
      </div>
    );
  }

  const handleSend = async () => {
    if (inputText.trim() && chat && user) {
      const text = inputText;
      const currentParticipant = participant;
      setInputText('');

      try {
        if (!currentParticipant || currentParticipant.id === 'unknown') {
          alert("No recipient found for this chat.");
          return;
        }

        // Client-side E2EE Flow (BB84 -> Dilithium -> Kyber)
        // 1. Get identity keys
        const myKeys = await StorageService.getIdentityKeys();
        const recipientKeys = participant.public_keys; // Expecting { kyber: string, dilithium: string }

        if (!myKeys || !recipientKeys?.kyber) {
          console.warn("Keys missing for hybrid encryption. Falling back to deterministic...");
          const sharedKey = await CryptoService.getSharedKeyForPeer(user.username, participant.id);
          const encryptedMessage = await CryptoService.encryptMessage(inputText, sharedKey);
          socket?.emit('send_message', {
            recipient_id: participant.id,
            encrypted_message: encryptedMessage,
            type: MessageType.TEXT,
            client_msg_id: `m_${Date.now()}`
          });
        } else {
          // 2. Perform Hybrid Encryption
          const hybridCt = await CryptoService.hybridEncrypt(
            inputText,
            myKeys.dilithiumSecKey,
            recipientKeys.kyber,
            user.username,
            participant.id
          );

          // 3. Send via Socket
          socket?.emit('send_message', {
            recipient_id: participant.id,
            encrypted_message: hybridCt, // This is the base64 wire package
            type: MessageType.TEXT,
            is_hybrid: true,
            client_msg_id: `m_${Date.now()}`
          });
        }

        // 4. Local Persist (Ephemerally)
        await StorageService.saveMessage({
          id: `m_${Date.now()}`,
          sender_id: user.username,
          sender_username: user.username,
          recipient_id: participant.id,
          content: inputText,
          type: 'text',
          timestamp: new Date().toISOString(),
          is_encrypted: true
        });

        // Optimistic UI update
        onSendMessage(text, MessageType.TEXT);

      } catch (error) {
        console.error('Failed to send message:', error);
        alert('Encryption failed. Secure link interrupted.');
      }
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !chat || !user) return;

    setIsUploading(true);
    try {
      const response = await FileService.uploadFile(file);
      const isImage = FileService.isImage(file.name);

      const msgType = isImage ? MessageType.IMAGE : MessageType.FILE;

      // Send message with file URL via socket
      const participant = chat.participants?.[0];
      if (participant) {
        socket?.emit('send_message', {
          recipient_id: participant.id,
          content: `Shared a file: ${file.name}`,
          type: msgType,
          mediaUrl: response.url,
          fileName: file.name,
          fileSize: (file.size / 1024).toFixed(1) + ' KB',
          client_msg_id: `m_${Date.now()}`
        });

        // Local save
        await StorageService.saveMessage({
          id: `m_${Date.now()}`,
          sender_id: user.username,
          sender_username: user.username,
          recipient_id: participant.id,
          content: file.name,
          type: isImage ? 'image' : 'file',
          url: response.url,
          timestamp: new Date().toISOString(),
          is_encrypted: false // TODO: Encrypt URL too
        });

        // Optimistic update (UI part)
        onSendMessage(file.name, msgType);
      }
    } catch (err) {
      alert('Upload failed');
    } finally {
      setIsUploading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  // const participant removed here as it is declared above

  return (
    <div className="flex-1 flex flex-col h-full bg-slate-50 dark:bg-black/90 relative font-sans selection:bg-emerald-500 selection:text-black border-l-4 border-black dark:border-white">
      {/* Stark Background Pattern */}
      <div className="absolute inset-0 pointer-events-none z-0 opacity-[0.03] dark:opacity-[0.05]"
        style={{ backgroundImage: 'linear-gradient(to right, #000 1px, transparent 1px), linear-gradient(to bottom, #000 1px, transparent 1px)', backgroundSize: '40px 40px' }} />

      {/* Header */}
      <div className="h-20 px-4 md:px-8 flex items-center justify-between bg-white dark:bg-black border-b-4 border-black dark:border-white z-10 shadow-[0px_4px_0px_#10b981]">
        <div className="flex items-center gap-4">
          {/* Mobile Back Button */}
          {onBack && (
            <button
              onClick={onBack}
              className="md:hidden p-2 border-2 border-black dark:border-white hover:bg-emerald-500 hover:text-black transition-colors"
              aria-label="Back to chats"
            >
              <ChevronLeft className="w-6 h-6" />
            </button>
          )}

          <div className="flex items-center cursor-pointer group" onClick={onToggleRightSidebar}>
            <div className="border-2 border-black dark:border-white bg-white shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] group-hover:translate-x-[1px] group-hover:translate-y-[1px] group-hover:shadow-[1px_1px_0px_#000] transition-all">
              <Avatar src={participant.avatar} alt={participant.name} status={participant.status as any} size="md" />
            </div>
            <div className="ml-4">
              <h3 className="font-black text-black dark:text-white uppercase tracking-tight text-lg">{participant.name}</h3>
              <div className="flex items-center font-mono text-[10px] uppercase font-bold tracking-widest">
                {participant.status === 'online' ? (
                  <span className="text-emerald-500">SYSTEM_ONLINE</span>
                ) : (
                  <span className="text-slate-500 dark:text-slate-400">LAST_PING: {participant.lastSeen}</span>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <div className="hidden md:flex items-center px-3 py-1.5 border-2 border-black dark:border-white bg-emerald-500 shadow-[2px_2px_0px_#000]">
            <LockIcon className="w-3.5 h-3.5 text-black mr-2" />
            <span className="text-[10px] font-black tracking-widest uppercase text-black">LINK_SECURED</span>
          </div>
          <button
            className="p-2 border-2 border-black dark:border-white bg-white dark:bg-black text-black dark:text-white shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] hover:bg-emerald-500 hover:text-black hover:translate-x-[1px] hover:translate-y-[1px] hover:shadow-[1px_1px_0px_#000] active:translate-x-[2px] active:translate-y-[2px] active:shadow-none transition-all"
            onClick={onToggleRightSidebar}
          >
            <MoreVertical className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 md:p-8 space-y-8 custom-scrollbar relative z-10">
        {chat.messages.map((msg, index) => {
          const isMe = msg.senderId === user?.username;
          const showAvatar = !isMe && (index === 0 || chat.messages[index - 1].senderId !== msg.senderId);

          return (
            <div
              key={msg.id}
              className={`flex ${isMe ? 'justify-end' : 'justify-start'} group animate-fade-in`}
            >
              {!isMe && (
                <div className={`mr-4 flex-shrink-0 w-10 ${!showAvatar && 'opacity-0'}`}>
                  <div className="border-2 border-black dark:border-white bg-white">
                    <Avatar src={participant.avatar} alt={participant.name} size="sm" showStatus={false} />
                  </div>
                </div>
              )}

              <div className={`max-w-[85%] md:max-w-[70%] relative ${isMe
                ? 'bg-emerald-500 text-black border-4 border-black dark:border-white shadow-[6px_6px_0px_#000] dark:shadow-[6px_6px_0px_#fff]'
                : 'bg-white dark:bg-black text-black dark:text-white border-4 border-black dark:border-white shadow-[6px_6px_0px_#10b981]'
                } p-4 md:p-5`}>

                {/* Message Content */}
                {msg.type === MessageType.TEXT && <p className="text-sm md:text-base font-bold leading-relaxed whitespace-pre-wrap">{msg.content}</p>}

                {msg.type === MessageType.IMAGE && (
                  <div className="mb-2 border-2 border-black dark:border-white bg-black dark:bg-white p-1">
                    <img src={msg.mediaUrl} alt="Shared" className="max-w-full h-auto object-cover" />
                    {msg.content && <p className="mt-3 text-sm font-bold text-white dark:text-black text-center">{msg.content}</p>}
                  </div>
                )}

                {msg.type === MessageType.FILE && (
                  <div className="flex items-center p-3 border-2 border-black dark:border-white bg-transparent">
                    <div className={`p-2 border-2 border-black dark:border-white mr-3 ${isMe ? 'bg-black text-white' : 'bg-black dark:bg-white text-white dark:text-black'}`}>
                      <FileText className="w-6 h-6" />
                    </div>
                    <div>
                      <p className="text-sm font-black uppercase tracking-tight truncate">{msg.fileName}</p>
                      <p className="font-mono text-[10px] font-bold uppercase tracking-widest mt-1 opacity-80">{msg.fileSize} • DATA_BLOB</p>
                    </div>
                  </div>
                )}

                {/* Metadata */}
                <div className={`flex items-center justify-end mt-3 space-x-2 font-mono text-[10px] font-bold uppercase tracking-widest ${isMe ? 'text-black/70 dark:text-white/70' : 'text-slate-500'}`}>
                  <span>{msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  {isMe && (
                    <span className="flex items-center border border-black dark:border-white p-0.5 rounded-[2px]">
                      {msg.status === 'read' ? <CheckCheck className="w-3 h-3 text-black dark:text-white" /> : <Check className="w-3 h-3 text-black dark:text-white" />}
                    </span>
                  )}
                </div>

                {/* Reactions */}
                {msg.reactions && msg.reactions.length > 0 && (
                  <div className={`absolute -bottom-4 ${isMe ? 'right-4' : 'left-4'} bg-white dark:bg-black border-2 border-black dark:border-white shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] px-2 py-0.5 flex items-center space-x-2 z-10`}>
                    {msg.reactions.map((r, i) => (
                      <span key={i} className="text-xs">{r.emoji}</span>
                    ))}
                    <span className="font-mono text-[10px] font-black">{msg.reactions.reduce((acc, curr) => acc + curr.count, 0)}</span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <div className="p-4 md:p-6 bg-white dark:bg-black border-t-4 border-black dark:border-white z-10 shadow-[0px_-4px_0px_#10b981]">
        <div className="flex items-end space-x-3 max-w-5xl mx-auto">
          <div className="relative">
            <button
              onClick={() => setShowEmojiPicker(!showEmojiPicker)}
              className={`p-3 border-2 border-black dark:border-white bg-transparent transition-colors shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] active:translate-x-[2px] active:translate-y-[2px] active:shadow-none hidden sm:block ${showEmojiPicker ? 'bg-emerald-500 text-black' : 'text-black dark:text-white hover:bg-emerald-500 hover:text-black'}`}
            >
              <Smile className="w-6 h-6" />
            </button>

            {showEmojiPicker && (
              <div className="absolute bottom-full mb-4 left-0 p-4 bg-white dark:bg-black border-4 border-black dark:border-white shadow-[8px_8px_0px_#10b981] z-[100] grid grid-cols-6 gap-2 w-64 animate-scale-in origin-bottom-left">
                {['😀', '😂', '😍', '😊', '🤔', '😎', '🔥', '👍', '🙏', '💯', '✨', '🎈', '🎉', '❤️', '✅', '🚀', '💀', '👽'].map(emoji => (
                  <button
                    key={emoji}
                    onClick={() => {
                      setInputText(prev => prev + emoji);
                      setShowEmojiPicker(false);
                    }}
                    className="p-2 text-xl hover:bg-emerald-500 hover:scale-110 transition-all border border-transparent hover:border-black rounded-sm"
                  >
                    {emoji}
                  </button>
                ))}
              </div>
            )}
          </div>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            className="hidden"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={isUploading}
            className={`p-3 border-2 border-black dark:border-white bg-transparent text-black dark:text-white transition-colors shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] active:translate-x-[2px] active:translate-y-[2px] active:shadow-none ${isUploading ? 'opacity-50 cursor-wait' : 'hover:bg-emerald-500 hover:text-black'}`}
          >
            <Paperclip className="w-6 h-6" />
          </button>

          <div className="flex-1 group">
            <textarea
              id="message-input"
              aria-label="Type a message"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="TRANSMIT_DATA..."
              rows={1}
              className="w-full bg-transparent border-4 border-black dark:border-white rounded-none focus:outline-none focus:border-emerald-500 resize-none max-h-32 text-black dark:text-white placeholder-slate-400 py-3.5 px-4 font-mono text-sm transition-colors uppercase custom-scrollbar shadow-[4px_4px_0px_#000] dark:shadow-[4px_4px_0px_#fff]"
              style={{ minHeight: '52px' }}
            />
          </div>

          <div className="flex items-end">
            <button
              onClick={handleSend}
              disabled={!inputText.trim()}
              className={`p-3 border-4 border-black dark:border-white shadow-[4px_4px_0px_#000] dark:shadow-[4px_4px_0px_#fff] transition-all 
                ${inputText.trim()
                  ? 'bg-emerald-500 text-black hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0px_#000] dark:hover:shadow-[2px_2px_0px_#fff] hover:bg-black hover:text-emerald-500 dark:hover:bg-white dark:hover:text-black active:shadow-none active:translate-x-[4px] active:translate-y-[4px]'
                  : 'bg-white dark:bg-black text-black/30 dark:text-white/30 cursor-not-allowed'
                }`}
              style={{ height: '52px', width: '52px' }}
            >
              <Send className="w-5 h-5 ml-0.5" />
            </button>
          </div>
        </div>
        <div className="text-center mt-4">
          <p className="font-mono text-[10px] font-bold uppercase tracking-widest text-black/60 dark:text-white/50 flex items-center justify-center gap-2">
            <LockIcon className="w-3 h-3" /> E2E_CRYPTO_ACTIVE: AES-256-GCM
          </p>
        </div>
      </div>
    </div>
  );
};

export default ChatWindow;
