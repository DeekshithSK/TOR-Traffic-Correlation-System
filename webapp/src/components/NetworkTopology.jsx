import { MapPin, Server, ArrowRight } from 'lucide-react';

export default function NetworkTopology({
    clientIP,
    clientLocation = 'Client',
    guardIP,
    guardLocation = 'Guard Node',
    guardCountry,
    guardFlag = '🌐'
}) {
    return (
        <div className="w-full p-6 rounded-xl bg-ops-panel border border-ops-border">
            <h4 className="text-[10px] font-bold text-text-tertiary uppercase tracking-widest mb-6">
                Network Topology
            </h4>

            <div className="relative flex items-center justify-between">
                {/* Client Node */}
                <div className="flex flex-col items-center text-center z-10">
                    <div className="w-16 h-16 rounded-full bg-ops-cyan/20 border-2 border-ops-cyan flex items-center justify-center shadow-glow-cyan">
                        <MapPin className="w-7 h-7 text-ops-cyan" />
                    </div>
                    <div className="mt-3">
                        <p className="text-sm font-bold text-white">Client</p>
                        <p className="text-xs text-text-tertiary font-mono mt-1">{clientIP}</p>
                        <p className="text-[10px] text-text-muted">Local Network</p>
                    </div>
                </div>

                {/* Connection Line with Animation */}
                <div className="flex-1 mx-4 relative">
                    {/* Base Line */}
                    <div className="absolute inset-y-1/2 left-0 right-0 h-0.5 bg-gradient-to-r from-ops-cyan via-intel to-threat" />

                    {/* Animated Packets */}
                    <div className="absolute inset-y-1/2 left-0 right-0 h-0.5 overflow-hidden">
                        <div className="absolute w-8 h-full bg-white/50 rounded-full animate-pulse"
                            style={{ animation: 'slide 2s linear infinite' }} />
                    </div>

                    {/* Arrow */}
                    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 
                          w-10 h-10 rounded-full bg-ops-panel border border-ops-border 
                          flex items-center justify-center">
                        <ArrowRight className="w-5 h-5 text-intel" />
                    </div>

                    {/* Tor Encrypted Label */}
                    <div className="absolute -bottom-6 left-1/2 -translate-x-1/2">
                        <span className="text-[9px] font-mono text-intel uppercase tracking-wider">
                            TLS Encrypted
                        </span>
                    </div>
                </div>

                {/* Guard Node */}
                <div className="flex flex-col items-center text-center z-10">
                    <div className="w-16 h-16 rounded-full bg-threat/20 border-2 border-threat flex items-center justify-center shadow-glow-red">
                        <Server className="w-7 h-7 text-threat" />
                    </div>
                    <div className="mt-3">
                        <p className="text-sm font-bold text-white">Guard Node</p>
                        <p className="text-xs text-text-tertiary font-mono mt-1">{guardIP}</p>
                        <p className="text-[10px] text-text-muted flex items-center justify-center gap-1">
                            <span>{guardFlag}</span>
                            <span>{guardCountry}</span>
                        </p>
                    </div>
                </div>
            </div>

            {/* Legend */}
            <div className="mt-10 pt-4 border-t border-ops-border flex justify-center gap-8 text-xs">
                <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-ops-cyan" />
                    <span className="text-text-secondary">Source (Client)</span>
                </div>
                <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-threat" />
                    <span className="text-text-secondary">Destination (Guard)</span>
                </div>
            </div>
        </div>
    );
}
