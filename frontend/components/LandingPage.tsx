
import React, { useState, useEffect } from 'react';
import { Shield, Smartphone, Lock, Globe, Zap, Users, ArrowRight, Menu, X, Check, CheckCircle, Server, Eye, FileKey, Moon, Sun } from 'lucide-react';

interface LandingPageProps {
  onNavigate: (page: 'login' | 'signup') => void;
  theme: 'light' | 'dark';
  setTheme: (theme: 'light' | 'dark') => void;
}

const LandingPage: React.FC<LandingPageProps> = ({ onNavigate, theme, setTheme }) => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <div className="min-h-screen bg-white dark:bg-[#0f172a] text-slate-900 dark:text-white overflow-x-hidden font-sans selection:bg-teal-500 selection:text-white">
      {/* Background Ambience */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div className="absolute top-0 left-0 w-full h-[800px] bg-gradient-to-br from-teal-500/10 via-purple-500/10 to-transparent opacity-60 dark:opacity-40" />
        <div className="absolute top-[20%] right-[10%] w-96 h-96 bg-purple-500/20 rounded-full blur-[100px] animate-pulse" />
        <div className="absolute bottom-[20%] left-[10%] w-72 h-72 bg-teal-500/20 rounded-full blur-[80px]" />
      </div>

      {/* Navigation */}
      <nav className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${isScrolled ? 'bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg shadow-lg py-3' : 'bg-transparent py-5'}`}>
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
          <div className="flex items-center gap-2 cursor-pointer group" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
            <div className="w-8 h-8 bg-gradient-to-br from-teal-400 to-purple-600 rounded-lg flex items-center justify-center shadow-lg group-hover:shadow-teal-500/30 transition-all">
              <Lock className="w-4 h-4 text-white" />
            </div>
            <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-teal-600 to-purple-600 dark:from-teal-400 dark:to-purple-400">AGES</span>
          </div>

          {/* Desktop Nav */}
          <div className="hidden md:flex items-center gap-8">
            <a href="#features" className="text-sm font-medium text-slate-600 dark:text-slate-300 hover:text-teal-500 dark:hover:text-teal-400 transition-colors">Features</a>
            <a href="#security" className="text-sm font-medium text-slate-600 dark:text-slate-300 hover:text-teal-500 dark:hover:text-teal-400 transition-colors">Security</a>
            <a href="#how-it-works" className="text-sm font-medium text-slate-600 dark:text-slate-300 hover:text-teal-500 dark:hover:text-teal-400 transition-colors">How It Works</a>
          </div>

          <div className="hidden md:flex items-center gap-4">
            {/* Theme Toggle */}
            <button
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
              className="p-2 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 transition-colors"
              aria-label="Toggle theme"
            >
              {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>

            <button
              onClick={() => onNavigate('login')}
              className="px-5 py-2 rounded-full text-sm font-semibold border border-teal-500/30 text-teal-600 dark:text-teal-400 hover:bg-teal-50 dark:hover:bg-teal-900/20 transition-all"
            >
              Sign In
            </button>
            <button
              onClick={() => onNavigate('signup')}
              className="px-5 py-2 rounded-full text-sm font-semibold bg-gradient-to-r from-teal-500 to-teal-600 text-white shadow-lg shadow-teal-500/30 hover:shadow-teal-500/50 hover:scale-105 transition-all"
            >
              Get Started
            </button>
          </div>

          {/* Mobile Menu Toggle */}
          <button className="md:hidden p-2" onClick={() => setMobileMenuOpen(true)}>
            <Menu className="w-6 h-6 text-slate-700 dark:text-slate-200" />
          </button>
        </div>
      </nav>

      {/* Mobile Menu Overlay */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-[60] bg-slate-900/95 backdrop-blur-xl flex flex-col p-8 animate-fade-in">
          <div className="flex justify-between items-center mb-12">
            <span className="text-xl font-bold text-white">Menu</span>
            <button onClick={() => setMobileMenuOpen(false)}><X className="w-6 h-6 text-white" /></button>
          </div>
          <div className="flex flex-col gap-6 text-center">
            <a href="#features" onClick={() => setMobileMenuOpen(false)} className="text-xl font-medium text-white/80">Features</a>
            <a href="#security" onClick={() => setMobileMenuOpen(false)} className="text-xl font-medium text-white/80">Security</a>
            <a href="#how-it-works" onClick={() => setMobileMenuOpen(false)} className="text-xl font-medium text-white/80">How It Works</a>

            {/* Theme Toggle for Mobile */}
            <button
              onClick={() => {
                setTheme(theme === 'dark' ? 'light' : 'dark');
                setMobileMenuOpen(false);
              }}
              className="flex items-center justify-center gap-2 text-xl font-medium text-white/80"
            >
              {theme === 'dark' ? (
                <><Sun className="w-5 h-5" /> Light Mode</>
              ) : (
                <><Moon className="w-5 h-5" /> Dark Mode</>
              )}
            </button>

            <button onClick={() => { setMobileMenuOpen(false); onNavigate('login'); }} className="text-xl font-medium text-teal-400">Sign In</button>
            <button onClick={() => { setMobileMenuOpen(false); onNavigate('signup'); }} className="py-3 bg-teal-500 rounded-xl text-white font-bold">Get Started</button>
          </div>
        </div>
      )}

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 md:pt-48 md:pb-32 px-6 overflow-hidden">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center gap-12 md:gap-20">
          <div className="flex-1 text-center md:text-left z-10">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-teal-500/10 border border-teal-500/20 text-teal-700 dark:text-teal-300 text-xs font-bold mb-6 animate-fade-in">
              <span className="w-2 h-2 rounded-full bg-teal-500 animate-pulse"></span>
              v2.0 Now Available
            </div>

            <h1 className="text-5xl md:text-7xl font-bold leading-tight tracking-tight mb-6 animate-slide-in-left">
              Private Messaging.<br />
              <span className="bg-clip-text text-transparent bg-gradient-to-r from-teal-500 to-purple-600">Without Phone Numbers.</span>
            </h1>

            <p className="text-lg md:text-xl text-slate-600 dark:text-slate-300 mb-8 max-w-xl mx-auto md:mx-0 leading-relaxed animate-slide-in-left" style={{ animationDelay: '100ms' }}>
              Connect with friends using usernames. Your conversations are end-to-end encrypted and completely private. No data mining, ever.
            </p>

            <div className="flex flex-col sm:flex-row items-center gap-4 justify-center md:justify-start animate-slide-in-left" style={{ animationDelay: '200ms' }}>
              <div className="relative w-full sm:w-auto">
                <input
                  type="email"
                  placeholder="Enter your email"
                  className="w-full sm:w-72 px-6 py-4 rounded-full bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 focus:outline-none focus:ring-2 focus:ring-teal-500 shadow-xl shadow-slate-200/50 dark:shadow-none"
                />
              </div>
              <button
                onClick={() => onNavigate('signup')}
                className="w-full sm:w-auto px-8 py-4 rounded-full bg-gradient-to-r from-teal-500 to-teal-600 text-white font-bold shadow-xl shadow-teal-500/30 hover:scale-105 transition-transform flex items-center justify-center gap-2"
              >
                Get Started Free <ArrowRight className="w-4 h-4" />
              </button>
            </div>

            <div className="mt-8 flex items-center justify-center md:justify-start gap-4 text-sm text-slate-500 dark:text-slate-400 animate-fade-in" style={{ animationDelay: '500ms' }}>
              <div className="flex -space-x-2">
                {[1, 2, 3, 4].map(i => (
                  <div key={i} className="w-8 h-8 rounded-full border-2 border-white dark:border-slate-900 bg-slate-200 dark:bg-slate-700 overflow-hidden">
                    <img src={`https://picsum.photos/100/100?random=${i + 10}`} alt="User" className="w-full h-full object-cover" />
                  </div>
                ))}
              </div>
              <span>Join 10,000+ users</span>
            </div>
          </div>

          <div className="flex-1 w-full relative z-10 animate-fade-in" style={{ animationDelay: '300ms' }}>
            <div className="relative mx-auto w-full max-w-[360px] md:max-w-md aspect-[9/19] bg-slate-900 rounded-[3rem] border-8 border-slate-800 shadow-2xl overflow-hidden ring-1 ring-white/10">
              {/* Fake App UI */}
              <div className="absolute inset-0 bg-slate-900 flex flex-col">
                <div className="h-24 bg-slate-800/50 backdrop-blur-md border-b border-white/5 flex items-end pb-4 px-6 gap-4">
                  <div className="w-10 h-10 rounded-full bg-gradient-to-br from-purple-500 to-indigo-500" />
                  <div className="flex-1 h-2 bg-slate-700 rounded-full w-1/2 mb-2" />
                </div>
                <div className="flex-1 p-4 space-y-4">
                  <div className="flex gap-3">
                    <div className="w-8 h-8 rounded-full bg-slate-700 shrink-0" />
                    <div className="bg-slate-800 p-3 rounded-2xl rounded-tl-none max-w-[80%]">
                      <div className="w-32 h-2 bg-slate-600 rounded-full mb-2" />
                      <div className="w-24 h-2 bg-slate-700 rounded-full" />
                    </div>
                  </div>
                  <div className="flex gap-3 flex-row-reverse">
                    <div className="bg-teal-600 p-3 rounded-2xl rounded-tr-none max-w-[80%]">
                      <div className="w-40 h-2 bg-white/40 rounded-full mb-2" />
                      <div className="w-20 h-2 bg-white/30 rounded-full" />
                    </div>
                  </div>
                  {/* Floating Elements */}
                  <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-white/10 backdrop-blur-xl p-4 rounded-xl border border-white/20 shadow-xl flex items-center gap-3 animate-bounce-soft">
                    <div className="w-10 h-10 rounded-full bg-green-500/20 flex items-center justify-center">
                      <Lock className="w-5 h-5 text-green-400" />
                    </div>
                    <div>
                      <div className="text-white text-xs font-bold">End-to-End Encrypted</div>
                      <div className="text-white/60 text-[10px]">Your chat is secure</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            {/* Decorative Glow behind phone */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full h-full bg-teal-500/20 blur-[80px] -z-10 rounded-full" />
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section id="features" className="py-24 bg-slate-50 dark:bg-slate-900/50">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Everything you need for secure messaging</h2>
            <p className="text-slate-500 dark:text-slate-400 max-w-2xl mx-auto">
              Powerful features designed with privacy in mind. We don't just encrypt your data; we ensure it stays yours.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            <FeatureCard
              icon={<Shield className="w-8 h-8 text-teal-500" />}
              title="End-to-End Encryption"
              description="Messages are encrypted on your device and can only be read by the recipient."
            />
            <FeatureCard
              icon={<Smartphone className="w-8 h-8 text-purple-500" />}
              title="No Phone Numbers"
              description="Sign up with just a username. Keep your personal phone number private."
            />
            <FeatureCard
              icon={<Zap className="w-8 h-8 text-orange-500" />}
              title="Instant & Fast"
              description="Built on a modern edge network for low-latency messaging anywhere."
            />
            <FeatureCard
              icon={<Globe className="w-8 h-8 text-blue-500" />}
              title="Cross-Platform"
              description="Seamlessly sync your conversations across mobile, web, and desktop."
            />
            <FeatureCard
              icon={<Users className="w-8 h-8 text-pink-500" />}
              title="Secure Groups"
              description="Create encrypted group chats with friends, family, or teams."
            />
            <FeatureCard
              icon={<Lock className="w-8 h-8 text-green-500" />}
              title="Zero Access"
              description="We can't read your messages even if we wanted to. Zero knowledge architecture."
            />
          </div>
        </div>
      </section>

      {/* Security Section */}
      <section id="security" className="py-24 bg-slate-900 text-white relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-slate-900 via-slate-900 to-teal-900/20"></div>
        <div className="max-w-7xl mx-auto px-6 relative z-10 flex flex-col md:flex-row items-center gap-16">
          <div className="flex-1">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-green-500/10 border border-green-500/20 text-green-400 text-xs font-bold mb-6">
              <Shield className="w-3 h-3" /> Bank-Level Security
            </div>
            <h2 className="text-4xl font-bold mb-6">Your privacy is our priority</h2>
            <p className="text-slate-400 text-lg mb-8 leading-relaxed">
              AGES uses the same encryption technology trusted by governments and financial institutions worldwide. Your messages are locked with a key that only you and the recipient have.
            </p>
            <ul className="space-y-4">
              {[
                "End-to-End Encryption (E2EE)",
                "Zero Access Architecture",
                "Perfect Forward Secrecy",
                "Open Source Protocols"
              ].map((item, i) => (
                <li key={i} className="flex items-center gap-3 text-slate-300">
                  <div className="w-6 h-6 rounded-full bg-green-500/20 flex items-center justify-center">
                    <Check className="w-4 h-4 text-green-400" />
                  </div>
                  {item}
                </li>
              ))}
            </ul>
          </div>
          <div className="flex-1">
            <div className="relative bg-white/5 backdrop-blur-xl rounded-2xl p-8 border border-white/10 shadow-2xl">
              <div className="absolute -top-10 -right-10 w-32 h-32 bg-teal-500/20 rounded-full blur-3xl"></div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-800/50 p-6 rounded-xl border border-white/5">
                  <Server className="w-8 h-8 text-teal-400 mb-4" />
                  <h4 className="font-bold mb-2">No Data Mining</h4>
                  <p className="text-xs text-slate-400">We don't sell your data or show ads. Ever.</p>
                </div>
                <div className="bg-slate-800/50 p-6 rounded-xl border border-white/5">
                  <Eye className="w-8 h-8 text-purple-400 mb-4" />
                  <h4 className="font-bold mb-2">No Tracking</h4>
                  <p className="text-xs text-slate-400">We don't track your location or activity.</p>
                </div>
                <div className="col-span-2 bg-slate-800/50 p-6 rounded-xl border border-white/5 flex items-center gap-6">
                  <FileKey className="w-10 h-10 text-orange-400" />
                  <div>
                    <h4 className="font-bold">Your Keys, Your Data</h4>
                    <p className="text-xs text-slate-400 mt-1">Private keys are generated on your device and never leave it.</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="how-it-works" className="py-24 bg-white dark:bg-slate-900">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Get started in minutes</h2>
            <p className="text-slate-500 dark:text-slate-400 max-w-2xl mx-auto">
              Creating your secure messaging account is fast, easy, and requires no personal information.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-12 relative">
            {/* Connector Line (Desktop) */}
            <div className="hidden md:block absolute top-12 left-[16%] right-[16%] h-0.5 bg-gradient-to-r from-teal-500/20 via-purple-500/20 to-teal-500/20 z-0"></div>

            <StepCard
              number="1"
              title="Create Account"
              description="Sign up with a unique username. No phone number or real name required."
            />
            <StepCard
              number="2"
              title="Add Friends"
              description="Share your username or QR code to connect with friends securely."
            />
            <StepCard
              number="3"
              title="Start Chatting"
              description="Send messages, photos, and files with total privacy and encryption."
            />
          </div>

          <div className="mt-16 text-center">
            <button
              onClick={() => onNavigate('signup')}
              className="px-10 py-4 rounded-full bg-slate-900 dark:bg-white text-white dark:text-slate-900 font-bold hover:scale-105 transition-transform shadow-xl"
            >
              Join AGES Now
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-slate-900 text-white py-12 border-t border-slate-800">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid md:grid-cols-4 gap-8 mb-12">
            <div className="col-span-1 md:col-span-2">
              <div className="flex items-center gap-2 mb-4">
                <Lock className="w-6 h-6 text-teal-500" />
                <span className="text-2xl font-bold">AGES</span>
              </div>
              <p className="text-slate-400 max-w-sm">
                Next-generation secure messaging platform. Privacy is a right, not a feature.
              </p>
            </div>
            <div>
              <h4 className="font-bold mb-4">Product</h4>
              <ul className="space-y-2 text-slate-400">
                <li><a href="#" className="hover:text-teal-400 transition-colors">Download</a></li>
                <li><a href="#features" className="hover:text-teal-400 transition-colors">Features</a></li>
                <li><a href="#security" className="hover:text-teal-400 transition-colors">Security</a></li>
              </ul>
            </div>
            <div>
              <h4 className="font-bold mb-4">Company</h4>
              <ul className="space-y-2 text-slate-400">
                <li><a href="#" className="hover:text-teal-400 transition-colors">About</a></li>
                <li><a href="#" className="hover:text-teal-400 transition-colors">Privacy Policy</a></li>
                <li><a href="#" className="hover:text-teal-400 transition-colors">Terms of Service</a></li>
              </ul>
            </div>
          </div>
          <div className="border-t border-slate-800 pt-8 flex flex-col md:flex-row justify-between items-center gap-4 text-slate-500 text-sm">
            <p>© 2025 AGES. All rights reserved.</p>
            <div className="flex gap-6">
              <span>Made with ❤️ for Privacy</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

const FeatureCard: React.FC<{ icon: React.ReactNode; title: string; description: string }> = ({ icon, title, description }) => (
  <div className="p-8 rounded-2xl bg-white dark:bg-slate-800 border border-slate-100 dark:border-slate-700 shadow-xl shadow-slate-200/50 dark:shadow-none hover:translate-y-[-5px] transition-transform duration-300">
    <div className="w-14 h-14 rounded-xl bg-slate-50 dark:bg-slate-700/50 flex items-center justify-center mb-6">
      {icon}
    </div>
    <h3 className="text-xl font-bold mb-3">{title}</h3>
    <p className="text-slate-500 dark:text-slate-400 leading-relaxed">
      {description}
    </p>
  </div>
);

const StepCard: React.FC<{ number: string; title: string; description: string }> = ({ number, title, description }) => (
  <div className="relative z-10 flex flex-col items-center text-center group">
    <div className="w-24 h-24 rounded-full bg-white dark:bg-slate-800 border-4 border-slate-100 dark:border-slate-700 flex items-center justify-center mb-6 shadow-xl group-hover:scale-110 transition-transform duration-300">
      <span className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-br from-teal-500 to-purple-600">{number}</span>
    </div>
    <h3 className="text-xl font-bold mb-3">{title}</h3>
    <p className="text-slate-500 dark:text-slate-400 max-w-xs">{description}</p>
  </div>
);

export default LandingPage;
