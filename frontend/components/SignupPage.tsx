
import React, { useState } from 'react';
import { User as UserIcon, Lock as LockIcon, Mail, ArrowRight, Shield, Check } from 'lucide-react';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

interface SignupPageProps {
   onLogin: () => void;
   onNavigateLogin: () => void;
   onNavigateHome: () => void;
}

const SignupPage: React.FC<SignupPageProps> = ({ onLogin, onNavigateLogin, onNavigateHome }) => {
   const [formData, setFormData] = useState({
      username: '',
      email: '',
      password: '',
      confirmPassword: ''
   });
   const [isLoading, setIsLoading] = useState(false);

   const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      setFormData({ ...formData, [e.target.name]: e.target.value });
   };

   const { login, register } = useAuth(); // Import useAuth

   const handleSubmit = async (e: React.FormEvent) => {
      e.preventDefault();
      if (formData.password !== formData.confirmPassword) {
         alert("Passwords do not match");
         return;
      }

      setIsLoading(true);
      const registrationEmail = formData.email.trim() || `${formData.username.trim()}@ages.internal`;

      try {
         await register(registrationEmail, formData.password, formData.username);
         onLogin();
      } catch (err: any) {
         alert(err.message || 'Registration failed');
      } finally {
         setIsLoading(false);
      }
   };

   return (
      <div className="min-h-screen flex items-center justify-center bg-white dark:bg-black relative overflow-hidden px-4 py-12 font-sans selection:bg-emerald-500 selection:text-black">
         {/* Stark Background Pattern */}
         <div className="fixed inset-0 pointer-events-none z-0 opacity-[0.03] dark:opacity-[0.05]"
            style={{ backgroundImage: 'linear-gradient(to right, #000 1px, transparent 1px), linear-gradient(to bottom, #000 1px, transparent 1px)', backgroundSize: '40px 40px' }} />

         <div className="relative w-full max-w-4xl bg-white dark:bg-black border-4 border-black dark:border-white shadow-[16px_16px_0px_#10b981] overflow-hidden flex flex-col md:flex-row z-10 animate-fade-in">
            {/* Left Side - Info */}
            <div className="hidden md:flex flex-col justify-between p-10 bg-emerald-500 text-black w-1/3 border-r-4 border-black dark:border-white">
               <div>
                  <div className="w-12 h-12 bg-black border-2 border-black flex items-center justify-center shadow-[4px_4px_0px_#000] mb-6 hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0px_#000] transition-all p-2">
                     <img src="/pwa-512x512.png" alt="AGIES" className="w-full h-full object-contain" />
                  </div>
                  <h2 className="text-3xl font-black text-black uppercase tracking-tighter mb-2">Initialize</h2>
                  <p className="font-mono text-xs text-black/80 font-bold uppercase tracking-widest leading-relaxed">Establish Secure Identity & Generate Cryptographic Keys.</p>
               </div>

               <div className="space-y-6">
                  <div className="flex gap-4">
                     <div className="w-8 h-8 border-2 border-black flex items-center justify-center shrink-0 text-black font-black text-sm shadow-[2px_2px_0px_#000]">1</div>
                     <div>
                        <h4 className="text-black font-black uppercase tracking-tight">Identity</h4>
                        <p className="font-mono text-black/70 text-[10px] mt-1 uppercase tracking-wider">Choose Handle</p>
                     </div>
                  </div>
                  <div className="flex gap-4">
                     <div className="w-8 h-8 border-2 border-black flex items-center justify-center shrink-0 text-black font-black text-sm shadow-[2px_2px_0px_#000]">2</div>
                     <div>
                        <h4 className="text-black font-black uppercase tracking-tight">Keys</h4>
                        <p className="font-mono text-black/70 text-[10px] mt-1 uppercase tracking-wider">Local Generation</p>
                     </div>
                  </div>
                  <div className="flex gap-4">
                     <div className="w-8 h-8 border-2 border-black flex items-center justify-center shrink-0 text-black font-black text-sm shadow-[2px_2px_0px_#000]">3</div>
                     <div>
                        <h4 className="text-black font-black uppercase tracking-tight">Connect</h4>
                        <p className="font-mono text-black/70 text-[10px] mt-1 uppercase tracking-wider">Zero Phone Numbers</p>
                     </div>
                  </div>
               </div>

               <p className="font-mono text-[10px] text-black font-bold uppercase tracking-widest">© 2025 SECURE.LINK PROTOCOL</p>
            </div>

            {/* Right Side - Form */}
            <div className="flex-1 p-8 md:p-12 relative">
               <div className="flex justify-between items-center mb-10 border-b-4 border-black dark:border-white pb-4">
                  <h2 className="text-4xl font-black text-black dark:text-white uppercase tracking-tighter">Registration</h2>
                  <button onClick={onNavigateHome} className="text-black dark:text-white font-bold hover:text-emerald-500 uppercase tracking-widest text-xs transition-colors">Abort</button>
               </div>

               <form onSubmit={handleSubmit} className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                     <div className="space-y-2">
                        <label className="text-xs font-bold text-black dark:text-white uppercase block tracking-wider">Target Handle</label>
                        <div className="relative group">
                           <UserIcon className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-black dark:text-white transition-colors" />
                           <input
                              name="username"
                              value={formData.username}
                              onChange={handleChange}
                              className="w-full bg-transparent border-2 border-black dark:border-white rounded-none py-3.5 pl-12 pr-4 text-black dark:text-white placeholder-slate-400 font-mono focus:outline-none focus:border-emerald-500 focus:ring-0 transition-colors"
                              placeholder="@GHOST_PROTOCOL"
                           />
                        </div>
                     </div>
                     <div className="space-y-2">
                        <label className="text-xs font-bold text-black dark:text-white uppercase block tracking-wider">Recovery Vector (Optional)</label>
                        <div className="relative group">
                           <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-black dark:text-white transition-colors" />
                           <input
                              name="email"
                              value={formData.email}
                              onChange={handleChange}
                              className="w-full bg-transparent border-2 border-black dark:border-white rounded-none py-3.5 pl-12 pr-4 text-black dark:text-white placeholder-slate-400 font-mono focus:outline-none focus:border-emerald-500 focus:ring-0 transition-colors"
                              placeholder="ANON@MAIL.COM"
                           />
                        </div>
                     </div>
                  </div>

                  <div className="space-y-2">
                     <label className="text-xs font-bold text-black dark:text-white uppercase block tracking-wider">Master Passphrase</label>
                     <div className="relative group">
                        <LockIcon className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-black dark:text-white transition-colors" />
                        <input
                           name="password"
                           type="password"
                           value={formData.password}
                           onChange={handleChange}
                           className="w-full bg-transparent border-2 border-black dark:border-white rounded-none py-3.5 pl-12 pr-4 text-black dark:text-white placeholder-slate-400 font-mono focus:outline-none focus:border-emerald-500 focus:ring-0 transition-colors"
                           placeholder="ENTROPY_REQUIRED"
                        />
                     </div>
                     {/* Brutalist Strength Meter */}
                     <div className="flex gap-1 mt-3">
                        <div className="flex-1 border-2 border-black dark:border-white bg-red-500 h-2"></div>
                        <div className="flex-1 border-2 border-black dark:border-white bg-yellow-500 h-2"></div>
                        <div className="flex-1 border-2 border-black dark:border-white bg-transparent h-2"></div>
                        <div className="flex-1 border-2 border-black dark:border-white bg-transparent h-2"></div>
                     </div>
                     <p className="font-mono text-[10px] text-right text-black dark:text-white uppercase tracking-widest font-bold mt-1">Status: Unstable</p>
                  </div>

                  <div className="space-y-2">
                     <label className="text-xs font-bold text-black dark:text-white uppercase block tracking-wider">Verify Passphrase</label>
                     <div className="relative group">
                        <LockIcon className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-black dark:text-white transition-colors" />
                        <input
                           name="confirmPassword"
                           type="password"
                           value={formData.confirmPassword}
                           onChange={handleChange}
                           className="w-full bg-transparent border-2 border-black dark:border-white rounded-none py-3.5 pl-12 pr-4 text-black dark:text-white placeholder-slate-400 font-mono focus:outline-none focus:border-emerald-500 focus:ring-0 transition-colors"
                           placeholder="CONFIRM_ENTROPY"
                        />
                     </div>
                  </div>

                  <div className="flex items-start gap-4 pt-4 border-t-2 border-black dark:border-white border-dashed">
                     <div className="mt-0.5">
                        <input type="checkbox" className="w-5 h-5 rounded-none border-2 border-black dark:border-white bg-transparent text-emerald-500 focus:ring-emerald-500 focus:ring-offset-0" />
                     </div>
                     <p className="text-xs font-mono font-bold uppercase text-black dark:text-white leading-relaxed">
                        I agree to the <a href="#" className="text-emerald-500 hover:text-black dark:hover:text-white transition-colors border-b-2 border-emerald-500 px-1">TOS</a> & <a href="#" className="text-emerald-500 hover:text-black dark:hover:text-white transition-colors border-b-2 border-emerald-500 px-1">PRIVACY</a>. I understand that if I lose my passphrase, MY DATA IS UNRECOVERABLE.
                     </p>
                  </div>

                  <button
                     type="submit"
                     disabled={isLoading}
                     className="w-full mt-6 bg-black dark:bg-white text-white dark:text-black font-black uppercase tracking-widest py-4 border-2 border-black dark:border-white shadow-[6px_6px_0px_#10b981] hover:translate-x-[3px] hover:translate-y-[3px] hover:shadow-[3px_3px_0px_#10b981] active:shadow-none active:translate-x-[6px] active:translate-y-[6px] transition-all disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center gap-3"
                  >
                     {isLoading ? (
                        <>Initializing Keys <div className="w-5 h-5 border-4 border-white/30 dark:border-black/30 border-t-white dark:border-t-black rounded-full animate-spin" /></>
                     ) : (
                        <>Execute Creation <ArrowRight className="w-6 h-6" /></>
                     )}
                  </button>
               </form>

               <div className="mt-8 text-center border-t-4 border-black dark:border-white pt-6">
                  <p className="text-black dark:text-white font-bold text-xs uppercase tracking-wide">
                     Already Cleared?{' '}
                     <button onClick={onNavigateLogin} className="text-emerald-500 font-black border-b-2 border-emerald-500 hover:bg-emerald-500 hover:text-black transition-colors px-1 ml-1">
                        AUTHENTICATE
                     </button>
                  </p>
               </div>
            </div>
         </div>
      </div>
   );
};

export default SignupPage;
