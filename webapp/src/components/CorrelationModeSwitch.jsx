import { Shield, Crosshair } from 'lucide-react';

export default function CorrelationModeSwitch({ mode, onModeChange }) {
    const modes = [
        {
            id: 'guard_only',
            label: 'Single-Side PCAP',
            description: 'Analyze single capture point',
            icon: Shield,
            color: 'ops-cyan'
        },
        {
            id: 'guard_exit',
            label: 'Dual-Side PCAP',
            description: 'Correlate entry + exit evidence',
            icon: Crosshair,
            color: 'secure'
        }
    ];

    return (
        <div className="w-full">
            <label className="text-xs font-bold text-text-tertiary uppercase tracking-widest mb-3 block">
                Correlation Mode
            </label>

            <div className="grid grid-cols-2 gap-3">
                {modes.map((m) => {
                    const Icon = m.icon;
                    const isActive = mode === m.id;

                    return (
                        <button
                            key={m.id}
                            onClick={() => onModeChange(m.id)}
                            className={`
                relative p-4 rounded-xl border-2 transition-all duration-200 text-left
                ${isActive
                                    ? `border-${m.color} bg-${m.color}/10 shadow-lg`
                                    : 'border-ops-border bg-ops-panel hover:border-ops-border/80'
                                }
              `}
                        >
                            {/* Active Indicator */}
                            {isActive && (
                                <div className={`absolute top-2 right-2 w-2 h-2 rounded-full bg-${m.color} animate-pulse`} />
                            )}

                            <div className="flex items-center gap-3 mb-2">
                                <div className={`
                  w-8 h-8 rounded-lg flex items-center justify-center
                  ${isActive ? `bg-${m.color}/20` : 'bg-ops-border/50'}
                `}>
                                    <Icon className={`w-4 h-4 ${isActive ? `text-${m.color}` : 'text-text-tertiary'}`} />
                                </div>
                                <span className={`font-semibold ${isActive ? 'text-white' : 'text-text-secondary'}`}>
                                    {m.label}
                                </span>
                            </div>

                            <p className="text-xs text-text-tertiary">
                                {m.description}
                            </p>
                        </button>
                    );
                })}
            </div>

            {/* Mode Info */}
            <div className="mt-3 p-3 rounded-lg bg-ops-black border border-ops-border">
                <p className="text-xs text-text-tertiary">
                    {mode === 'guard_only'
                        ? '📋 Single-Side: Analyzes traffic from one capture point (e.g., victim server).'
                        : '📋 Dual-Side: Correlates evidence from two capture points for enhanced confidence.'
                    }
                </p>
            </div>
        </div>
    );
}
