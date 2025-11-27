
import React, { useState, useEffect, useRef } from 'react';
import { 
  X, Settings, Share2, Download, Palette, Camera, Image as ImageIcon, 
  Flashlight, UserPlus, Check, ChevronRight, RefreshCw, Smartphone
} from 'lucide-react';
import Avatar from './Avatar';
import { User } from '../types';

interface QRCodeModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentUser: User;
}

const QRCodeModal: React.FC<QRCodeModalProps> = ({ isOpen, onClose, currentUser }) => {
  const [activeTab, setActiveTab] = useState<'my-code' | 'scan-code'>('my-code');
  const [qrColor, setQrColor] = useState('21808D'); // Default teal
  const [showCustomization, setShowCustomization] = useState(false);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black/80 backdrop-blur-sm transition-opacity animate-fade-in"
        onClick={onClose}
      />

      {/* Modal Container */}
      <div className="relative w-full max-w-2xl bg-white dark:bg-slate-900 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh] animate-scale-in border border-white/10">
        
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-100 dark:border-gray-800 bg-white/50 dark:bg-slate-900/50 backdrop-blur-md z-10">
          <button 
            onClick={onClose}
            className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
          
          <div className="flex bg-gray-100 dark:bg-slate-800 rounded-full p-1 relative">
            <div 
              className={`absolute top-1 bottom-1 w-1/2 bg-white dark:bg-slate-700 rounded-full shadow-sm transition-all duration-300 ${activeTab === 'my-code' ? 'left-1' : 'left-[48%]'}`} 
            />
            <button 
              onClick={() => setActiveTab('my-code')}
              className={`relative px-4 py-1.5 text-sm font-medium rounded-full transition-colors z-10 ${activeTab === 'my-code' ? 'text-teal-600 dark:text-teal-400' : 'text-gray-500'}`}
            >
              My Code
            </button>
            <button 
              onClick={() => setActiveTab('scan-code')}
              className={`relative px-4 py-1.5 text-sm font-medium rounded-full transition-colors z-10 ${activeTab === 'scan-code' ? 'text-teal-600 dark:text-teal-400' : 'text-gray-500'}`}
            >
              Scan Code
            </button>
          </div>

          <button 
            onClick={() => activeTab === 'my-code' ? setShowCustomization(!showCustomization) : null}
            className={`p-2 rounded-full transition-colors ${activeTab === 'my-code' ? 'hover:bg-gray-100 dark:hover:bg-slate-800 text-gray-500' : 'opacity-0 pointer-events-none'}`}
          >
            <Settings className="w-5 h-5" />
          </button>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto overflow-x-hidden relative bg-gray-50 dark:bg-[#0f172a]">
          {activeTab === 'my-code' ? (
            <MyCodeTab 
              user={currentUser} 
              qrColor={qrColor} 
              setQrColor={setQrColor}
              showCustomization={showCustomization}
              setShowCustomization={setShowCustomization}
            />
          ) : (
            <ScanCodeTab onClose={onClose} />
          )}
        </div>
      </div>
    </div>
  );
};

// --- My Code Tab ---

interface MyCodeTabProps {
  user: User;
  qrColor: string;
  setQrColor: (color: string) => void;
  showCustomization: boolean;
  setShowCustomization: (show: boolean) => void;
}

const MyCodeTab: React.FC<MyCodeTabProps> = ({ 
  user, qrColor, setQrColor, showCustomization, setShowCustomization 
}) => {
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=https://ages.app/add/${user.username}&color=${qrColor}&bgcolor=FFFFFF&margin=10`;

  const handleDownload = async () => {
    try {
      const response = await fetch(qrUrl);
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `AGES_QR_${user.username.replace('@', '')}.png`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (e) {
      console.error('Download failed', e);
    }
  };

  const handleShare = async () => {
    if (navigator.share) {
      try {
        await navigator.share({
          title: 'Join me on AGES',
          text: `Connect with me on AGES Secure Messaging! My username is ${user.username}`,
          url: `https://ages.app/add/${user.username}`,
        });
      } catch (err) {
        console.error('Share failed', err);
      }
    } else {
      alert('Sharing is not supported on this browser.');
    }
  };

  return (
    <div className="flex h-full relative">
      <div className="flex-1 flex flex-col items-center justify-center p-8 space-y-8 min-h-[500px]">
        {/* QR Card */}
        <div className="relative group">
          <div className="absolute -inset-1 bg-gradient-to-r from-teal-400 to-purple-500 rounded-2xl blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
          <div className="relative p-6 bg-white rounded-xl shadow-xl flex flex-col items-center">
            <div className="w-[280px] h-[280px] rounded-lg overflow-hidden relative">
              <img 
                src={qrUrl} 
                alt="QR Code" 
                className="w-full h-full object-contain" 
              />
              {/* Center Logo Overlay */}
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                 <div className="bg-white p-1 rounded-full shadow-md">
                   <Avatar src={user.avatar} alt={user.name} size="md" showStatus={false} />
                 </div>
              </div>
            </div>
            
            <div className="mt-6 flex flex-col items-center">
              <h3 className="text-xl font-bold text-gray-900">{user.username}</h3>
              <p className="text-gray-500 text-sm">Scan to add me on AGES</p>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-col w-full max-w-xs gap-3">
          <button 
            onClick={handleShare}
            className="flex items-center justify-center w-full py-3 bg-teal-500 hover:bg-teal-600 text-white rounded-xl font-medium shadow-lg shadow-teal-500/30 transition-all active:scale-95"
          >
            <Share2 className="w-5 h-5 mr-2" />
            Share QR Code
          </button>
          <div className="flex gap-3">
             <button 
              onClick={handleDownload}
              className="flex-1 flex items-center justify-center py-3 bg-white dark:bg-slate-800 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-slate-700 text-gray-700 dark:text-gray-200 rounded-xl font-medium transition-all active:scale-95"
            >
              <Download className="w-5 h-5 mr-2" />
              Save
            </button>
             <button 
              onClick={() => setShowCustomization(!showCustomization)}
              className="flex-1 flex items-center justify-center py-3 bg-white dark:bg-slate-800 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-slate-700 text-gray-700 dark:text-gray-200 rounded-xl font-medium transition-all active:scale-95"
            >
              <Palette className="w-5 h-5 mr-2" />
              Style
            </button>
          </div>
        </div>
      </div>

      {/* Customization Side Panel */}
      <div className={`absolute right-0 top-0 bottom-0 w-64 bg-white/95 dark:bg-slate-900/95 backdrop-blur-md border-l border-gray-200 dark:border-gray-800 transform transition-transform duration-300 z-20 ${showCustomization ? 'translate-x-0' : 'translate-x-full'}`}>
         <div className="p-4 border-b border-gray-200 dark:border-gray-800 flex justify-between items-center">
           <h3 className="font-semibold text-gray-900 dark:text-white">Customize QR</h3>
           <button onClick={() => setShowCustomization(false)}>
             <X className="w-5 h-5 text-gray-500" />
           </button>
         </div>
         <div className="p-4 space-y-6">
           <div>
             <label className="text-xs font-semibold text-gray-500 uppercase mb-3 block">Pattern Color</label>
             <div className="grid grid-cols-4 gap-2">
               {['000000', '21808D', '7C3AED', 'DB2777', 'EA580C', '16A34A', '2563EB', '475569'].map(color => (
                 <button
                   key={color}
                   onClick={() => setQrColor(color)}
                   className={`w-10 h-10 rounded-full border-2 transition-all ${qrColor === color ? 'border-gray-900 dark:border-white scale-110' : 'border-transparent hover:scale-105'}`}
                   style={{ backgroundColor: `#${color}` }}
                 />
               ))}
             </div>
           </div>
         </div>
      </div>
    </div>
  );
};

// --- Scan Code Tab ---

interface ScanCodeTabProps {
  onClose: () => void;
}

const ScanCodeTab: React.FC<ScanCodeTabProps> = ({ onClose }) => {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [permission, setPermission] = useState<'granted' | 'denied' | 'prompt'>('prompt');
  const [scanning, setScanning] = useState(true);
  const [result, setResult] = useState<User | null>(null);

  useEffect(() => {
    let stream: MediaStream | null = null;

    const startCamera = async () => {
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          setPermission('granted');
        }
      } catch (err) {
        console.error("Camera error:", err);
        setPermission('denied');
      }
    };

    if (scanning && !result) {
      startCamera();
    }

    return () => {
      if (stream) {
        stream.getTracks().forEach(track => track.stop());
      }
    };
  }, [scanning, result]);

  // Simulation of finding a code
  useEffect(() => {
    if (permission === 'granted' && scanning && !result) {
      const timer = setTimeout(() => {
        setScanning(false);
        setResult({
          id: 'new_user',
          name: 'Jennifer Wu',
          username: '@jenwu_design',
          avatar: 'https://picsum.photos/200/200?random=44',
          status: 'online',
          bio: 'UX Researcher 🔍',
          mutualFriends: 4
        });
      }, 3500); // Detect after 3.5s
      return () => clearTimeout(timer);
    }
  }, [permission, scanning, result]);

  const resetScan = () => {
    setResult(null);
    setScanning(true);
  };

  if (result) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8 animate-fade-in bg-white dark:bg-slate-900">
        <div className="w-24 h-24 bg-green-100 rounded-full flex items-center justify-center mb-6 animate-bounce-soft">
           <Check className="w-10 h-10 text-green-600" />
        </div>
        <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">QR Code Detected!</h3>
        
        {/* User Card */}
        <div className="w-full max-w-sm bg-white dark:bg-slate-800 border border-gray-200 dark:border-gray-700 rounded-2xl p-6 shadow-xl my-6 flex flex-col items-center">
          <Avatar src={result.avatar} alt={result.name} size="xl" status="online" className="mb-4" />
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">{result.name}</h2>
          <p className="text-teal-600 dark:text-teal-400 font-medium mb-1">{result.username}</p>
          <p className="text-gray-500 dark:text-gray-400 text-sm text-center mb-4">{result.bio}</p>
          
          <div className="flex items-center text-xs text-gray-400 mb-6">
            <span className="flex -space-x-2 mr-2">
               {[1,2,3].map(i => (
                 <div key={i} className="w-6 h-6 rounded-full bg-gray-300 dark:bg-gray-600 border-2 border-white dark:border-slate-800"></div>
               ))}
            </span>
            {result.mutualFriends} Mutual Friends
          </div>

          <button className="w-full py-3 bg-teal-500 hover:bg-teal-600 text-white rounded-xl font-bold shadow-lg shadow-teal-500/20 transition-all transform active:scale-95 flex items-center justify-center">
             <UserPlus className="w-5 h-5 mr-2" />
             Add Friend
          </button>
        </div>

        <button 
          onClick={resetScan}
          className="flex items-center text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
        >
          <RefreshCw className="w-4 h-4 mr-2" />
          Scan Another
        </button>
      </div>
    );
  }

  return (
    <div className="relative h-full bg-black flex flex-col">
      {/* Camera View */}
      <div className="flex-1 relative overflow-hidden">
        {permission === 'granted' ? (
          <video 
            ref={videoRef} 
            autoPlay 
            playsInline 
            className="absolute inset-0 w-full h-full object-cover"
          />
        ) : (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-gray-400 bg-gray-900">
             {permission === 'denied' ? (
               <>
                 <Camera className="w-16 h-16 mb-4 opacity-50" />
                 <p className="text-center px-8">Camera access denied. Please check your browser settings.</p>
               </>
             ) : (
               <div className="animate-pulse">Requesting camera access...</div>
             )}
          </div>
        )}

        {/* Scan Overlay */}
        <div className="absolute inset-0 flex items-center justify-center z-10">
           <div className="relative w-64 h-64">
             {/* Corners */}
             <div className="absolute top-0 left-0 w-8 h-8 border-t-4 border-l-4 border-teal-500 rounded-tl-lg"></div>
             <div className="absolute top-0 right-0 w-8 h-8 border-t-4 border-r-4 border-teal-500 rounded-tr-lg"></div>
             <div className="absolute bottom-0 left-0 w-8 h-8 border-b-4 border-l-4 border-teal-500 rounded-bl-lg"></div>
             <div className="absolute bottom-0 right-0 w-8 h-8 border-b-4 border-r-4 border-teal-500 rounded-br-lg"></div>
             
             {/* Scanning Line */}
             {scanning && permission === 'granted' && (
               <div className="absolute left-0 right-0 h-0.5 bg-teal-500 shadow-[0_0_15px_rgba(45,212,191,0.8)] animate-scan"></div>
             )}

             {/* Helper Text */}
             <div className="absolute -bottom-16 left-0 right-0 text-center">
               <p className="text-white/80 text-sm font-medium drop-shadow-md">Align QR code within frame</p>
             </div>
           </div>
           
           {/* Dark Overlay Outside Frame */}
           <div className="absolute inset-0 bg-black/50 mask-image-scan-frame pointer-events-none"></div>
        </div>
      </div>

      {/* Bottom Controls */}
      <div className="h-24 bg-black/80 backdrop-blur-md flex items-center justify-between px-8 z-20">
         <button className="flex flex-col items-center gap-1 text-white/70 hover:text-white transition-colors">
            <div className="w-10 h-10 rounded-full bg-white/10 flex items-center justify-center">
              <ImageIcon className="w-5 h-5" />
            </div>
            <span className="text-[10px]">Gallery</span>
         </button>

         <button 
           onClick={() => alert("Simulate Flash Toggle")}
           className="flex flex-col items-center gap-1 text-white/70 hover:text-white transition-colors transform -translate-y-4"
         >
            <div className="w-14 h-14 rounded-full bg-teal-600 flex items-center justify-center shadow-lg shadow-teal-500/40">
              <Flashlight className="w-6 h-6 text-white" />
            </div>
         </button>

         <button 
          onClick={() => alert("Enter ID manually")}
          className="flex flex-col items-center gap-1 text-white/70 hover:text-white transition-colors"
         >
            <div className="w-10 h-10 rounded-full bg-white/10 flex items-center justify-center">
              <Smartphone className="w-5 h-5" />
            </div>
            <span className="text-[10px]">Enter ID</span>
         </button>
      </div>
    </div>
  );
};

export default QRCodeModal;
