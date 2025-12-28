import { useState, useEffect } from 'react';
import { Shield, Clock, Cpu, Database } from 'lucide-react';

export default function Header({ caseId, systemStatus = 'online' }) {
    const [currentTime, setCurrentTime] = useState(new Date());

    useEffect(() => {
        const timer = setInterval(() => setCurrentTime(new Date()), 1000);
        return () => clearInterval(timer);
    }, []);

    const formatTime = (date) => {
        return date.toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    };

    const formatDate = (date) => {
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: '2-digit'
        }).toUpperCase();
    };

    return (
        <header className="fixed top-0 left-0 right-0 z-[100] bg-ops-black border-b border-ops-border">
            <div className="container mx-auto px-6">
                <div className="flex items-center justify-between h-14">

                    {}
                    <div className="flex items-center gap-3 flex-shrink-0">
                        <div className="relative">
                            <div className="w-9 h-9 rounded-lg gradient-ops flex items-center justify-center">
                                <Shield className="w-4 h-4 text-white" />
                            </div>
                            <div className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-secure rounded-full border-2 border-ops-black" />
                        </div>
                        <div className="hidden sm:block">
                            <h1 className="text-sm font-bold text-white tracking-tight leading-none">
                                TOR FORENSICS
                            </h1>
                            <p className="text-[9px] text-text-tertiary font-mono uppercase tracking-wider">
                                Correlation Intel
                            </p>
                        </div>
                    </div>

                    {}
                    <div className="flex items-center gap-4">
                        <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-ops-panel border border-ops-border">
                            <div className={`w-1.5 h-1.5 rounded-full ${systemStatus === 'online' ? 'bg-secure animate-pulse' : 'bg-threat'}`} />
                            <span className="text-[10px] font-mono text-text-secondary uppercase">
                                {systemStatus === 'online' ? 'System Online' : 'Offline'}
                            </span>
                        </div>

                        <div className="hidden lg:flex items-center gap-3 text-[10px] text-text-tertiary">
                            <div className="flex items-center gap-1">
                                <Cpu className="w-3 h-3 text-ops-cyan" />
                                <span className="font-mono">MPS</span>
                            </div>
                            <div className="flex items-center gap-1">
                                <Database className="w-3 h-3 text-secure" />
                                <span className="font-mono">READY</span>
                            </div>
                        </div>
                    </div>

                    {}
                    <div className="flex items-center gap-4 flex-shrink-0">
                        {caseId && (
                            <div className="hidden md:block px-2 py-1 rounded bg-ops-panel border border-ops-border">
                                <span className="text-[10px] font-mono text-text-secondary">{caseId}</span>
                            </div>
                        )}

                        <div className="flex items-center gap-2 text-right">
                            <Clock className="w-3.5 h-3.5 text-text-tertiary hidden sm:block" />
                            <div>
                                <div className="text-xs font-mono font-semibold text-white tabular-nums leading-none">
                                    {formatTime(currentTime)}
                                </div>
                                <div className="text-[9px] font-mono text-text-tertiary leading-none mt-0.5">
                                    {formatDate(currentTime)}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </header>
    );
}
