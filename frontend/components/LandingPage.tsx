
import React, { useState, useEffect } from 'react';
import { Shield, Smartphone, Lock as LockIcon, Globe, Zap, Users, ArrowRight, Menu, X, Check, CheckCircle, Server, Eye, FileKey, Moon, Sun } from 'lucide-react';

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
      {/* Stark Background */}
      <div className="fixed inset-0 pointer-events-none z-0 bg-white dark:bg-black" />

      {/* Grid Pattern overlay for tech feel */}
      <div className="fixed inset-0 pointer-events-none z-0 opacity-[0.03] dark:opacity-[0.05]"
        style={{ backgroundImage: 'linear-gradient(to right, #000 1px, transparent 1px), linear-gradient(to bottom, #000 1px, transparent 1px)', backgroundSize: '40px 40px' }} />

      {/* Navigation */}
      <nav className={`fixed top-0 left-0 right-0 z-50 transition-all duration-200 border-b border-transparent ${isScrolled ? 'bg-white dark:bg-black border-black/10 dark:border-white/10 py-3' : 'bg-transparent py-5'}`}>
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
          <div className="flex items-center gap-3 cursor-pointer group" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
            <div className="w-8 h-8 bg-emerald-500 flex items-center justify-center shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] group-hover:translate-x-[1px] group-hover:translate-y-[1px] group-hover:shadow-[1px_1px_0px_#000] dark:group-hover:shadow-[1px_1px_0px_#fff] transition-all">
              <LockIcon className="w-4 h-4 text-black" />
            </div>
            <span className="text-2xl font-black text-black dark:text-white tracking-tighter">AGES.</span>
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
              className="p-2 border-2 border-transparent hover:border-black dark:hover:border-white text-black dark:text-white transition-colors"
              aria-label="Toggle theme"
            >
              {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>

            <button
              onClick={() => onNavigate('login')}
              className="px-6 py-2.5 font-bold border-2 border-black dark:border-white text-black dark:text-white hover:bg-black hover:text-white dark:hover:bg-white dark:hover:text-black transition-colors"
            >
              Sign In
            </button>
            <button
              onClick={() => onNavigate('signup')}
              className="px-6 py-2.5 font-bold bg-emerald-500 text-black border-2 border-black dark:border-white shadow-[4px_4px_0px_#000] dark:shadow-[4px_4px_0px_#fff] hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0px_#000] dark:hover:shadow-[2px_2px_0px_#fff] transition-all"
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
        <div className="fixed inset-0 z-[60] bg-white dark:bg-black flex flex-col p-8 animate-fade-in border-4 border-black dark:border-white m-4 shadow-[16px_16px_0px_#10b981]">
          <div className="flex justify-between items-center mb-12 border-b-4 border-black dark:border-white pb-4">
            <span className="text-2xl font-black text-black dark:text-white uppercase tracking-tighter">Menu</span>
            <button onClick={() => setMobileMenuOpen(false)} className="bg-black dark:bg-white p-2">
              <X className="w-6 h-6 text-white dark:text-black" />
            </button>
          </div>
          <div className="flex flex-col gap-8 text-center">
            <a href="#features" onClick={() => setMobileMenuOpen(false)} className="text-2xl font-black text-black dark:text-white uppercase tracking-tight hover:text-emerald-500 transition-colors">Features</a>
            <a href="#security" onClick={() => setMobileMenuOpen(false)} className="text-2xl font-black text-black dark:text-white uppercase tracking-tight hover:text-emerald-500 transition-colors">Security</a>
            <a href="#how-it-works" onClick={() => setMobileMenuOpen(false)} className="text-2xl font-black text-black dark:text-white uppercase tracking-tight hover:text-emerald-500 transition-colors">How It Works</a>

            <div className="h-0.5 bg-black dark:bg-white opacity-10 my-4" />

            {/* Theme Toggle for Mobile */}
            <button
              onClick={() => {
                setTheme(theme === 'dark' ? 'light' : 'dark');
                setMobileMenuOpen(false);
              }}
              className="flex items-center justify-center gap-3 text-xl font-bold text-black dark:text-white uppercase tracking-widest"
            >
              {theme === 'dark' ? (
                <><Sun className="w-6 h-6" /> Light Mode</>
              ) : (
                <><Moon className="w-6 h-6" /> Dark Mode</>
              )}
            </button>

            <button
              onClick={() => { setMobileMenuOpen(false); onNavigate('login'); }}
              className="text-2xl font-black text-emerald-500 uppercase border-2 border-emerald-500 py-4 hover:bg-emerald-500 hover:text-black transition-all"
            >
              Sign In
            </button>
            <button
              onClick={() => { setMobileMenuOpen(false); onNavigate('signup'); }}
              className="py-5 bg-emerald-500 text-black font-black uppercase tracking-widest border-2 border-black dark:border-white shadow-[6px_6px_0px_#000] dark:shadow-[6px_6px_0px_#fff]"
            >
              Get Started
            </button>
          </div>
        </div>
      )}

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 md:pt-48 md:pb-32 px-6 overflow-hidden">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center gap-12 md:gap-20">
          <div className="flex-1 text-center md:text-left z-10">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 bg-black dark:bg-white text-white dark:text-black text-xs font-bold mb-8 uppercase tracking-widest animate-fade-in">
              <span className="w-2 h-2 bg-emerald-500 animate-pulse"></span>
              PQC & QKD SECURED
            </div>

            <h1 className="text-6xl md:text-8xl font-black leading-[0.9] tracking-tighter mb-8 animate-slide-in-left text-black dark:text-white">
              ZERO<br />
              COMPROMISE.
            </h1>

            <p className="text-xl md:text-2xl text-slate-600 dark:text-slate-400 mb-10 max-w-xl mx-auto md:mx-0 font-medium animate-slide-in-left leading-snug" style={{ animationDelay: '100ms' }}>
              True post-quantum messaging. No phone numbers. No analytics. Physics-based security for a paranoid world.
            </p>

            <div className="flex flex-col sm:flex-row items-center gap-4 justify-center md:justify-start animate-slide-in-left" style={{ animationDelay: '200ms' }}>
              <button
                onClick={() => onNavigate('signup')}
                className="w-full sm:w-auto px-10 py-5 bg-emerald-500 text-black font-black text-lg border-2 border-black dark:border-white shadow-[6px_6px_0px_#000] dark:shadow-[6px_6px_0px_#fff] hover:translate-x-[3px] hover:translate-y-[3px] hover:shadow-[3px_3px_0px_#000] dark:hover:shadow-[3px_3px_0px_#fff] transition-all flex items-center justify-center gap-3 uppercase"
              >
                Deploy Now <ArrowRight className="w-5 h-5" />
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
            <div className="relative mx-auto w-full max-w-[360px] md:max-w-md aspect-[9/19] bg-white dark:bg-black border-4 border-black dark:border-white shadow-[12px_12px_0px_#000] dark:shadow-[12px_12px_0px_#fff] overflow-hidden">
              {/* Fake App UI - Brutalist */}
              <div className="absolute inset-0 flex flex-col">
                <div className="h-20 bg-black dark:bg-white text-white dark:text-black border-b-4 border-black dark:border-white flex items-end pb-4 px-6 gap-4">
                  <div className="font-black text-2xl uppercase tracking-tighter">SECURE.LINK</div>
                </div>
                <div className="flex-1 p-4 space-y-4 bg-gray-50 dark:bg-black">
                  <div className="flex gap-0 flex-col">
                    <div className="bg-black dark:bg-white text-white dark:text-black p-4 border-2 border-black dark:border-white self-start max-w-[85%] relative">
                      <div className="font-mono text-[10px] opacity-70 mb-1 uppercase tracking-wider">KYBER_CHEM_ESTABLISHED</div>
                      <div className="w-32 h-2.5 bg-current opacity-20 mb-2" />
                      <div className="w-24 h-2.5 bg-current opacity-20" />
                    </div>
                  </div>
                  <div className="flex gap-0 flex-col">
                    <div className="bg-emerald-500 text-black p-4 border-2 border-black dark:border-white self-end max-w-[85%] relative">
                      <div className="font-mono text-[10px] opacity-70 mb-1 uppercase tracking-wider">BB84_QKD_SYNCED</div>
                      <div className="w-40 h-2.5 bg-black opacity-20 mb-2" />
                      <div className="w-20 h-2.5 bg-black opacity-20" />
                    </div>
                  </div>
                  {/* Floating Brutalist Card */}
                  <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-black dark:bg-white text-white dark:text-black p-4 border-4 border-black dark:border-white shadow-[8px_8px_0px_#10b981] flex items-center gap-4 animate-bounce-soft">
                    <div className="w-10 h-10 bg-emerald-500 flex items-center justify-center">
                      <LockIcon className="w-6 h-6 text-black" />
                    </div>
                    <div>
                      <div className="text-sm font-black uppercase tracking-tight">QKD Secured</div>
                      <div className="font-mono text-[10px] opacity-70 block">Eavesdropping impossible</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section id="features" className="py-24 bg-white dark:bg-black border-y-2 border-black dark:border-white">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-left mb-16 border-b-8 border-emerald-500 pb-8 inline-block">
            <h2 className="text-5xl md:text-6xl font-black uppercase tracking-tighter">System Specs.</h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-0 border-2 border-black dark:border-white bg-white dark:bg-black overflow-hidden shadow-[12px_12px_0px_#10b981]">
            <FeatureCard
              icon={<Shield className="w-10 h-10" />}
              title="End-to-End Encryption"
              description="Mathematical & physical guarantees. Zero data in transit visibility."
            />
            <FeatureCard
              icon={<Smartphone className="w-10 h-10" />}
              title="Zero Phone Numbers"
              description="Complete anonymity. Connect via cryptographic identity only."
            />
            <FeatureCard
              icon={<Zap className="w-10 h-10" />}
              title="Low Latency"
              description="Websocket protocol optimizations over quantum channels."
            />
            <FeatureCard
              icon={<Globe className="w-10 h-10" />}
              title="Post-Quantum Ready"
              description="CRYSTALS-Kyber KEM and Dilithium signatures built-in."
            />
            <FeatureCard
              icon={<Users className="w-10 h-10" />}
              title="Distributed Security"
              description="Decentralized key management architecture."
            />
            <FeatureCard
              icon={<LockIcon className="w-10 h-10" />}
              title="Zero Access"
              description="We physically cannot read your data. Period."
            />
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="how-it-works" className="py-24 bg-white dark:bg-black overflow-hidden">
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex flex-col md:flex-row items-start gap-16">
            <div className="md:w-1/3">
              <div className="inline-block bg-black dark:bg-white text-white dark:text-black px-4 py-1 text-xs font-black uppercase tracking-widest mb-6">
                Protocol.02
              </div>
              <h2 className="text-5xl font-black uppercase tracking-tighter mb-8 leading-none text-black dark:text-white">
                How It<br />Operates.
              </h2>
              <p className="text-slate-600 dark:text-slate-400 font-medium mb-8">
                A hybrid approach combining the physical security of Quantum Key Distribution with the mathematical strength of Post-Quantum Cryptography.
              </p>
              <div className="w-full h-1 bg-emerald-500" />
            </div>

            <div className="flex-1 space-y-12">
              {[
                {
                  step: "01",
                  title: "Identity Initialization",
                  desc: "Generate your local cryptographic identity. No phone numbers or emails are stored on our servers. Your private key never leaves your device."
                },
                {
                  step: "02",
                  title: "Quantum Key Exchange",
                  desc: "When connecting to a peer, a quantum-secure channel is established using Kyber KEM. We verify the link using Dilithium digital signatures."
                },
                {
                  step: "03",
                  title: "Encrypted Transmission",
                  desc: "Messages are fragmented and encrypted locally. Even if the backend node is compromised, your data remains an unreadable stream of entropy."
                }
              ].map((item, i) => (
                <div key={i} className="flex gap-8 group">
                  <div className="text-4xl font-black text-emerald-500 opacity-30 group-hover:opacity-100 transition-opacity">
                    {item.step}
                  </div>
                  <div className="pt-1">
                    <h4 className="text-2xl font-black uppercase tracking-tight mb-3 text-black dark:text-white">{item.title}</h4>
                    <p className="text-slate-600 dark:text-slate-400 font-medium leading-relaxed max-w-xl">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
      <section id="security" className="py-24 bg-emerald-500 text-black border-b-2 border-black dark:border-white relative">
        <div className="max-w-7xl mx-auto px-6 relative z-10 flex flex-col md:flex-row items-stretch gap-0 border-2 border-black bg-white dark:bg-black dark:border-white shadow-[12px_12px_0px_#000] dark:shadow-[12px_12px_0px_#fff]">
          <div className="flex-1 p-12 border-b-2 md:border-b-0 md:border-r-2 border-black dark:border-white">
            <h2 className="text-5xl font-black mb-6 uppercase tracking-tighter text-black dark:text-white">The Threat Model</h2>
            <p className="text-slate-600 dark:text-slate-400 text-lg mb-8 font-medium">
              We assume the network is already compromised. Data is encrypted using algorithms resistant to future quantum computing attacks (HNDL mitigation).
            </p>
            <ul className="space-y-4 font-mono text-sm uppercase text-black dark:text-white">
              {[
                "Kyber KEM Encapsulation",
                "Dilithium Signatures",
                "QBER Threat Detection",
                "Decoy-State Protocol"
              ].map((item, i) => (
                <li key={i} className="flex items-center gap-4">
                  <div className="w-6 h-6 bg-emerald-500 flex items-center justify-center border-2 border-black dark:border-white">
                    <Check className="w-4 h-4 text-black" />
                  </div>
                  {item}
                </li>
              ))}
            </ul>
          </div>
          <div className="flex-1 bg-black text-emerald-500 p-12 flex flex-col justify-center">
            <div className="font-mono text-sm leading-relaxed">
              <span className="text-red-500 font-bold">WARNING:</span> CLASSICAL ENCRYPTION IS OBSOLETE.<br /><br />
              Shor's Algorithm threatens RSA/ECC. Our implementation utilizes lattice-based cryptography, heavily tested under the NIST PQC standardization process, rendering quantum decryption attempts mathematically infeasible.
              <br /><br />
              <span className="text-white">STATUS: OVER-SECURED</span>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-black text-white py-12 border-t-4 border-emerald-500">
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex flex-col md:flex-row justify-between items-end gap-8 mb-12">
            <div>
              <div className="flex items-center gap-3 mb-4">
                <div className="w-8 h-8 bg-emerald-500 flex items-center justify-center">
                  <LockIcon className="w-5 h-5 text-black" />
                </div>
                <span className="text-3xl font-black uppercase tracking-tighter">AGES.</span>
              </div>
              <p className="text-slate-400 font-mono text-xs uppercase max-w-sm">
                Cryptographic Messaging Interface.<br />Version 2.0 / Secure Mode
              </p>
            </div>
            <div className="text-right">
              <button
                onClick={() => window.scrollTo(0, 0)}
                className="px-6 py-3 border-2 border-white hover:bg-emerald-500 hover:text-black hover:border-emerald-500 font-bold uppercase transition-colors"
              >
                Return to Top
              </button>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

const FeatureCard: React.FC<{ icon: React.ReactNode; title: string; description: string }> = ({ icon, title, description }) => (
  <div className="p-10 bg-white dark:bg-black border border-black/10 dark:border-white/10 hover:bg-emerald-500 dark:hover:bg-emerald-500 transition-all duration-300 group relative overflow-hidden">
    <div className="absolute top-0 left-0 w-2 h-0 bg-black dark:bg-white group-hover:h-full transition-all duration-300" />
    <div className="mb-8 text-emerald-500 group-hover:text-black dark:group-hover:text-black transition-colors">
      {icon}
    </div>
    <h3 className="text-2xl font-black mb-4 uppercase tracking-tighter text-black dark:text-white group-hover:text-black dark:group-hover:text-black transition-colors">{title}</h3>
    <p className="text-slate-600 dark:text-slate-400 group-hover:text-black font-medium leading-relaxed transition-colors">
      {description}
    </p>
  </div>
);

export default LandingPage;
