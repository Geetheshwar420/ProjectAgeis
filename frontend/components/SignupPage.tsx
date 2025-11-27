
import React, { useState } from 'react';
import { User, Lock, Mail, ArrowRight, Shield, Check } from 'lucide-react';
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

   const { login } = useAuth(); // Import useAuth

   const handleSubmit = async (e: React.FormEvent) => {
      e.preventDefault();
      if (formData.password !== formData.confirmPassword) {
         alert("Passwords do not match");
         return;
      }

      setIsLoading(true);
      try {
         const response = await api.post('/register', {
            username: formData.username,
            email: formData.email,
            password: formData.password
         });
         login(response.data.user);
         onLogin();
      } catch (err: any) {
         alert(err.response?.data?.error || 'Registration failed');
      } finally {
         setIsLoading(false);
      }
   };

   return (
      <div className="min-h-screen flex items-center justify-center bg-[#0f172a] relative overflow-hidden px-4 py-12">
         {/* Dynamic Background */}
         <div className="absolute inset-0">
            <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-slate-900 via-slate-900 to-slate-800" />
            <div className="absolute bottom-[0%] left-[20%] w-[60%] h-[60%] rounded-full bg-teal-500/5 blur-[100px] animate-pulse" />
         </div>

         <div className="relative w-full max-w-4xl bg-white/5 backdrop-blur-xl border border-white/10 rounded-3xl shadow-2xl overflow-hidden flex flex-col md:flex-row animate-scale-in">
            {/* Left Side - Info */}
            <div className="hidden md:flex flex-col justify-between p-10 bg-gradient-to-br from-teal-900/40 to-slate-900/40 w-1/3 border-r border-white/5">
               <div>
                  <div className="w-12 h-12 bg-teal-500 rounded-xl flex items-center justify-center shadow-lg shadow-teal-500/20 mb-6">
                     <Shield className="w-6 h-6 text-white" />
                  </div>
                  <h2 className="text-2xl font-bold text-white mb-2">Join AGES</h2>
                  <p className="text-teal-200/70 leading-relaxed">Create your encrypted identity and start communicating securely.</p>
               </div>

               <div className="space-y-6">
                  <div className="flex gap-4">
                     <div className="w-8 h-8 rounded-full bg-teal-500/20 flex items-center justify-center shrink-0 text-teal-400 font-bold text-sm">1</div>
                     <div>
                        <h4 className="text-white font-medium">Create ID</h4>
                        <p className="text-slate-400 text-xs mt-1">Choose a unique username</p>
                     </div>
                  </div>
                  <div className="flex gap-4">
                     <div className="w-8 h-8 rounded-full bg-teal-500/20 flex items-center justify-center shrink-0 text-teal-400 font-bold text-sm">2</div>
                     <div>
                        <h4 className="text-white font-medium">Generate Keys</h4>
                        <p className="text-slate-400 text-xs mt-1">Automatic local encryption</p>
                     </div>
                  </div>
                  <div className="flex gap-4">
                     <div className="w-8 h-8 rounded-full bg-teal-500/20 flex items-center justify-center shrink-0 text-teal-400 font-bold text-sm">3</div>
                     <div>
                        <h4 className="text-white font-medium">Start Chatting</h4>
                        <p className="text-slate-400 text-xs mt-1">Connect without phone numbers</p>
                     </div>
                  </div>
               </div>

               <p className="text-xs text-slate-500">© 2025 AGES Inc.</p>
            </div>

            {/* Right Side - Form */}
            <div className="flex-1 p-8 md:p-12">
               <div className="flex justify-between items-center mb-8">
                  <h2 className="text-2xl font-bold text-white">Create Account</h2>
                  <button onClick={onNavigateHome} className="text-slate-500 hover:text-white text-sm">Cancel</button>
               </div>

               <form onSubmit={handleSubmit} className="space-y-5">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                     <div className="space-y-2">
                        <label className="text-sm font-medium text-slate-300">Username</label>
                        <div className="relative">
                           <User className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                           <input
                              name="username"
                              value={formData.username}
                              onChange={handleChange}
                              className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 pl-10 pr-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-500/50"
                              placeholder="Ex: @alexrivera"
                           />
                        </div>
                     </div>
                     <div className="space-y-2">
                        <label className="text-sm font-medium text-slate-300">Email (Optional)</label>
                        <div className="relative">
                           <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                           <input
                              name="email"
                              value={formData.email}
                              onChange={handleChange}
                              className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 pl-10 pr-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-500/50"
                              placeholder="For account recovery"
                           />
                        </div>
                     </div>
                  </div>

                  <div className="space-y-2">
                     <label className="text-sm font-medium text-slate-300">Password</label>
                     <div className="relative">
                        <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                        <input
                           name="password"
                           type="password"
                           value={formData.password}
                           onChange={handleChange}
                           className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 pl-10 pr-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-500/50"
                           placeholder="Create a strong password"
                        />
                     </div>
                     {/* Strength Meter */}
                     <div className="flex gap-1 mt-2 h-1">
                        <div className="flex-1 bg-red-500 rounded-full opacity-100"></div>
                        <div className="flex-1 bg-yellow-500 rounded-full opacity-50"></div>
                        <div className="flex-1 bg-green-500 rounded-full opacity-20"></div>
                        <div className="flex-1 bg-green-500 rounded-full opacity-20"></div>
                     </div>
                     <p className="text-xs text-slate-500 text-right">Weak password</p>
                  </div>

                  <div className="space-y-2">
                     <label className="text-sm font-medium text-slate-300">Confirm Password</label>
                     <div className="relative">
                        <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                        <input
                           name="confirmPassword"
                           type="password"
                           value={formData.confirmPassword}
                           onChange={handleChange}
                           className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 pl-10 pr-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-500/50"
                           placeholder="Repeat password"
                        />
                     </div>
                  </div>

                  <div className="flex items-start gap-3 pt-2">
                     <div className="mt-1">
                        <input type="checkbox" className="w-4 h-4 rounded border-slate-700 bg-slate-800 text-teal-500 focus:ring-teal-500" />
                     </div>
                     <p className="text-xs text-slate-400">
                        I agree to the <a href="#" className="text-teal-400 hover:underline">Terms of Service</a> and <a href="#" className="text-teal-400 hover:underline">Privacy Policy</a>. I understand that if I lose my password, my encrypted data cannot be recovered.
                     </p>
                  </div>

                  <button
                     type="submit"
                     disabled={isLoading}
                     className="w-full mt-4 bg-gradient-to-r from-teal-500 to-teal-600 hover:from-teal-400 hover:to-teal-500 text-white font-bold py-4 rounded-xl shadow-lg shadow-teal-500/20 transition-all transform hover:scale-[1.01] active:scale-[0.98] disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  >
                     {isLoading ? (
                        <>Generating Keys <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /></>
                     ) : (
                        <>Create Account <ArrowRight className="w-5 h-5" /></>
                     )}
                  </button>
               </form>

               <div className="mt-8 text-center border-t border-white/5 pt-6">
                  <p className="text-slate-400 text-sm">
                     Already have an account?{' '}
                     <button onClick={onNavigateLogin} className="text-teal-400 font-bold hover:text-teal-300 transition-colors">
                        Sign in
                     </button>
                  </p>
               </div>
            </div>
         </div>
      </div>
   );
};

export default SignupPage;
