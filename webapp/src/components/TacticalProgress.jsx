export default function TacticalProgress({
    progress = 0,
    size = 120,
    strokeWidth = 8,
    variant = 'default',
    showPercentage = true,
    label,
    className = ''
}) {
    const radius = (size - strokeWidth) / 2;
    const circumference = radius * 2 * Math.PI;
    const offset = circumference - (progress / 100) * circumference;

    const colors = {
        default: { track: '#21262d', progress: '#58a6ff', glow: 'rgba(88, 166, 255, 0.3)', text: 'text-ops-cyan' },
        threat: { track: '#21262d', progress: '#f85149', glow: 'rgba(248, 81, 73, 0.3)', text: 'text-threat' },
        secure: { track: '#21262d', progress: '#3fb950', glow: 'rgba(63, 185, 80, 0.3)', text: 'text-secure' },
        intel: { track: '#21262d', progress: '#d29922', glow: 'rgba(210, 153, 34, 0.3)', text: 'text-intel' }
    };

    const config = colors[variant] || colors.default;

    return (
        <div className={`relative inline-flex items-center justify-center ${className}`}>
            <svg width={size} height={size} className="transform -rotate-90">
                <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={config.track} strokeWidth={strokeWidth} />
                <circle
                    cx={size / 2} cy={size / 2} r={radius} fill="none"
                    stroke={config.progress} strokeWidth={strokeWidth} strokeLinecap="round"
                    strokeDasharray={circumference}
                    strokeDashoffset={offset}
                    style={{
                        filter: `drop-shadow(0 0 10px ${config.glow})`,
                        transition: 'stroke-dashoffset 1s ease-out'
                    }}
                />
                {Array.from({ length: 20 }).map((_, i) => {
                    const angle = (i * 18 - 90) * (Math.PI / 180);
                    const x1 = size / 2 + (radius - strokeWidth / 2) * Math.cos(angle);
                    const y1 = size / 2 + (radius - strokeWidth / 2) * Math.sin(angle);
                    const x2 = size / 2 + (radius + strokeWidth / 2) * Math.cos(angle);
                    const y2 = size / 2 + (radius + strokeWidth / 2) * Math.sin(angle);
                    return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#0a0c10" strokeWidth={1} />;
                })}
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
                {showPercentage && (
                    <span className={`text-2xl font-bold font-mono ${config.text}`}>
                        {Math.round(progress)}%
                    </span>
                )}
                {label && <span className="text-[10px] text-text-tertiary uppercase tracking-wider mt-1">{label}</span>}
            </div>
        </div>
    );
}

export function LinearProgress({ progress = 0, variant = 'default', showPercentage = true, height = 8, className = '' }) {
    const colorMap = {
        default: 'from-ops-cyan to-ops-purple',
        threat: 'from-threat to-threat-dark',
        secure: 'from-secure to-secure-dark',
        intel: 'from-intel to-intel-dark'
    };

    return (
        <div className={`w-full ${className}`}>
            <div className="w-full bg-ops-border rounded-full overflow-hidden" style={{ height }}>
                <div
                    className={`h-full bg-gradient-to-r ${colorMap[variant] || colorMap.default} rounded-full transition-all duration-500 ease-out`}
                    style={{ width: `${progress}%` }}
                />
            </div>
            {showPercentage && (
                <div className="flex justify-between mt-1">
                    <span className="text-[10px] text-text-tertiary uppercase">Progress</span>
                    <span className="text-xs font-mono text-text-secondary">{Math.round(progress)}%</span>
                </div>
            )}
        </div>
    );
}
