import React, { ErrorInfo, ReactNode } from 'react';

interface Props {
    children: ReactNode;
}

interface State {
    hasError: boolean;
    error: Error | null;
}

class ErrorBoundary extends React.Component<Props, State> {
    state: { hasError: boolean; error: any; };
    props: any;
    constructor(props: Props) {
        super(props);
        this.state = {
            hasError: false,
            error: null
        };
    }

    static getDerivedStateFromError(error: Error): State {
        return {
            hasError: true,
            error
        };
    }

    componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        console.error('ErrorBoundary caught an error:', error, errorInfo);
    }

    render() {
        if (this.state.hasError) {
            return (
                <div className="flex h-screen w-screen flex-col items-center justify-center bg-slate-900 p-8 text-center text-white">
                    <div className="mb-8 p-4 border-4 border-emerald-500 bg-black shadow-[8px_8px_0px_#10b981]">
                        <h1 className="text-4xl font-black uppercase tracking-tighter text-emerald-500">CORE_MODULE_FAILURE</h1>
                    </div>
                    <p className="font-mono text-sm uppercase tracking-widest text-slate-400 mb-8">
                        The UI encountered a critical runtime exception. The signal has been intercepted.
                    </p>
                    <div className="max-w-2xl w-full p-6 border-2 border-red-500 bg-black/50 font-mono text-xs text-red-500 text-left overflow-auto max-h-48 mb-8">
                        {this.state.error?.message || 'Unknown Error'}
                    </div>
                    <button
                        onClick={() => window.location.reload()}
                        className="px-8 py-4 border-4 border-white bg-white text-black font-black uppercase tracking-widest hover:bg-emerald-500 hover:border-emerald-500 transition-all shadow-[4px_4px_0px_rgba(255,255,255,0.3)]"
                    >
                        Restart Terminal
                    </button>
                </div>
            );
        }

        return this.props.children;
    }
}

export default ErrorBoundary;
