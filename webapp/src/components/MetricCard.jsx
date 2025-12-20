import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

export default function MetricCard({
    label, value, unit = '', icon: Icon, trend, trendValue, variant = 'default', className = ''
}) {
    const TrendIcon = trend === 'up' ? TrendingUp : trend === 'down' ? TrendingDown : Minus;
    const trendColor = trend === 'up' ? 'text-secure' : trend === 'down' ? 'text-threat' : 'text-text-tertiary';
    const variantClasses = { default: 'p-6', large: 'p-8', compact: 'p-4' };

    return (
        <div className={`panel panel-glow ${variantClasses[variant]} ${className}`}>
            <div className="flex items-start justify-between mb-4">
                {Icon && (
                    <div className="w-10 h-10 rounded-xl bg-ops-cyan/10 flex items-center justify-center">
                        <Icon className="w-5 h-5 text-ops-cyan" />
                    </div>
                )}
                {trend && (
                    <div className={`flex items-center gap-1 ${trendColor}`}>
                        <TrendIcon className="w-4 h-4" />
                        {trendValue && <span className="text-xs font-mono">{trendValue}</span>}
                    </div>
                )}
            </div>
            <div className="space-y-1">
                <div className="flex items-baseline gap-2">
                    <span className={`font-bold font-mono text-white ${variant === 'large' ? 'text-5xl' : variant === 'compact' ? 'text-2xl' : 'text-4xl'}`}>
                        {value}
                    </span>
                    {unit && <span className="text-lg text-ops-cyan font-medium">{unit}</span>}
                </div>
                <p className="text-xs text-text-tertiary uppercase tracking-wider font-semibold">{label}</p>
            </div>
        </div>
    );
}

export function ConfidenceMetric({ score, sessions, className = '' }) {
    const percentage = (score * 100).toFixed(1);

    return (
        <div className={`flex gap-8 ${className}`}>
            <div>
                <div className="flex items-baseline gap-1">
                    <span className="text-5xl font-bold text-white font-mono">{percentage}</span>
                    <span className="text-xl text-ops-cyan font-semibold">%</span>
                </div>
                <p className="text-xs text-text-tertiary uppercase tracking-widest font-bold mt-1">Confidence</p>
            </div>
            <div className="w-px bg-ops-border" />
            <div>
                <span className="text-5xl font-bold text-white font-mono">{sessions}</span>
                <p className="text-xs text-text-tertiary uppercase tracking-widest font-bold mt-1">Sessions</p>
            </div>
        </div>
    );
}
