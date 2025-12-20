import { AlertTriangle, CheckCircle, AlertCircle, Info, ShieldAlert } from 'lucide-react';

const variants = {
    critical: {
        bg: 'bg-threat/10',
        border: 'border-threat/30',
        text: 'text-threat',
        dot: 'bg-threat',
        icon: ShieldAlert,
        animate: 'animate-threat'
    },
    high: {
        bg: 'bg-threat/10',
        border: 'border-threat/30',
        text: 'text-threat',
        dot: 'bg-threat',
        icon: AlertTriangle,
        animate: ''
    },
    medium: {
        bg: 'bg-intel/10',
        border: 'border-intel/30',
        text: 'text-intel',
        dot: 'bg-intel',
        icon: AlertCircle,
        animate: ''
    },
    low: {
        bg: 'bg-secure/10',
        border: 'border-secure/30',
        text: 'text-secure',
        dot: 'bg-secure',
        icon: CheckCircle,
        animate: ''
    },
    info: {
        bg: 'bg-ops-cyan/10',
        border: 'border-ops-cyan/30',
        text: 'text-ops-cyan',
        dot: 'bg-ops-cyan',
        icon: Info,
        animate: ''
    },
    secure: {
        bg: 'bg-secure/10',
        border: 'border-secure/30',
        text: 'text-secure',
        dot: 'bg-secure',
        icon: CheckCircle,
        animate: 'animate-secure'
    }
};

export default function StatusBadge({
    variant = 'info',
    label,
    showDot = true,
    showIcon = false,
    size = 'default', // 'small', 'default', 'large'
    pulse = false,
    className = ''
}) {
    const config = variants[variant] || variants.info;
    const Icon = config.icon;

    const sizeClasses = {
        small: 'text-[10px] px-2 py-0.5 gap-1',
        default: 'text-xs px-3 py-1 gap-1.5',
        large: 'text-sm px-4 py-1.5 gap-2'
    };

    const dotSizes = {
        small: 'w-1 h-1',
        default: 'w-1.5 h-1.5',
        large: 'w-2 h-2'
    };

    const iconSizes = {
        small: 'w-3 h-3',
        default: 'w-3.5 h-3.5',
        large: 'w-4 h-4'
    };

    return (
        <span
            className={`
        inline-flex items-center rounded-full font-semibold uppercase tracking-wider
        ${config.bg} ${config.border} ${config.text} border
        ${sizeClasses[size]}
        ${pulse ? config.animate : ''}
        ${className}
      `}
        >
            {showIcon && <Icon className={iconSizes[size]} />}
            {showDot && !showIcon && (
                <span className={`${dotSizes[size]} rounded-full ${config.dot} ${pulse ? 'animate-pulse' : ''}`} />
            )}
            {label}
        </span>
    );
}

// Threat Level Badge specifically for forensic results
export function ThreatLevelBadge({ level, score }) {
    const getLevel = () => {
        if (score >= 0.75) return { variant: 'high', label: 'HIGH CONFIDENCE' };
        if (score >= 0.50) return { variant: 'medium', label: 'MEDIUM CONFIDENCE' };
        return { variant: 'low', label: 'LOW CONFIDENCE' };
    };

    const config = level ? { variant: level.toLowerCase(), label: `${level.toUpperCase()} CONFIDENCE` } : getLevel();

    return (
        <StatusBadge
            variant={config.variant}
            label={config.label}
            showIcon={true}
            size="large"
            pulse={config.variant === 'high' || config.variant === 'critical'}
        />
    );
}
