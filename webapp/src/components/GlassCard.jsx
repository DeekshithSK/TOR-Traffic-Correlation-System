import { motion } from 'framer-motion';

export default function GlassCard({
    children,
    className = '',
    variant = 'default', // default, glow, threat, secure
    animated = false,
    onClick,
    ...props
}) {
    const baseClasses = 'glass rounded-2xl overflow-hidden relative';

    const variantClasses = {
        default: 'border-ops-border',
        glow: 'panel-glow',
        threat: 'border-threat/30 shadow-glow-red',
        secure: 'border-secure/30 shadow-glow-green',
        intel: 'border-intel/30 shadow-glow-amber'
    };

    const Component = animated ? motion.div : 'div';
    const animationProps = animated ? {
        initial: { opacity: 0, y: 20 },
        animate: { opacity: 1, y: 0 },
        exit: { opacity: 0, y: -10 },
        transition: { duration: 0.3 }
    } : {};

    return (
        <Component
            className={`${baseClasses} ${variantClasses[variant] || variantClasses.default} ${className}`}
            onClick={onClick}
            {...animationProps}
            {...props}
        >
            {}
            {variant === 'glow' && (
                <div className="scan-overlay opacity-30" />
            )}

            {}
            <div className="relative z-10">
                {children}
            </div>
        </Component>
    );
}

export function CardHeader({ title, icon: Icon, badge, action, className = '' }) {
    return (
        <div className={`flex items-center justify-between px-6 py-4 border-b border-ops-border ${className}`}>
            <div className="flex items-center gap-3">
                {Icon && (
                    <div className="w-8 h-8 rounded-lg bg-ops-cyan/10 flex items-center justify-center">
                        <Icon className="w-4 h-4 text-ops-cyan" />
                    </div>
                )}
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                    {title}
                </h3>
                {badge && (
                    <span className="badge badge-ops text-[10px]">{badge}</span>
                )}
            </div>
            {action && (
                <div className="text-xs text-text-secondary">
                    {action}
                </div>
            )}
        </div>
    );
}

export function CardBody({ children, className = '' }) {
    return (
        <div className={`p-6 ${className}`}>
            {children}
        </div>
    );
}

export function CardFooter({ children, className = '' }) {
    return (
        <div className={`px-6 py-4 border-t border-ops-border bg-ops-black/30 ${className}`}>
            {children}
        </div>
    );
}
