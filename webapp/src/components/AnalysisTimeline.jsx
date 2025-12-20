import { Check, Loader, Circle, Clock } from 'lucide-react';

const stepStates = {
    completed: { icon: Check, dotClass: 'bg-secure border-secure', lineClass: 'bg-secure', textClass: 'text-text-primary' },
    active: { icon: Loader, dotClass: 'bg-ops-cyan border-ops-cyan', lineClass: 'bg-ops-border', textClass: 'text-ops-cyan' },
    pending: { icon: Circle, dotClass: 'bg-transparent border-ops-border', lineClass: 'bg-ops-border', textClass: 'text-text-tertiary' }
};

export default function AnalysisTimeline({ steps, currentStep = 0 }) {
    const getStepState = (index) => {
        if (index < currentStep) return 'completed';
        if (index === currentStep) return 'active';
        return 'pending';
    };

    return (
        <div className="space-y-0">
            {steps.map((step, index) => {
                const state = getStepState(index);
                const config = stepStates[state];
                const Icon = config.icon;
                const isLast = index === steps.length - 1;

                return (
                    <div key={index} className="relative flex gap-4">
                        <div className="flex flex-col items-center">
                            <div className={`w-10 h-10 rounded-full border-2 flex items-center justify-center ${config.dotClass} ${state === 'active' ? 'shadow-glow-cyan animate-pulse' : ''}`}>
                                <Icon className={`w-5 h-5 ${state === 'completed' ? 'text-white' : state === 'active' ? 'text-white animate-spin' : 'text-ops-border'}`} />
                            </div>
                            {!isLast && <div className={`w-0.5 h-16 ${config.lineClass}`} />}
                        </div>
                        <div className="flex-1 pb-8">
                            <div className="flex items-start justify-between">
                                <div>
                                    <h4 className={`text-sm font-semibold ${config.textClass}`}>{step.title}</h4>
                                    <p className="text-xs text-text-tertiary mt-1 max-w-md">{step.description}</p>
                                </div>
                                {(step.duration || step.timestamp) && (
                                    <div className="flex items-center gap-1 text-xs text-text-tertiary font-mono">
                                        <Clock className="w-3 h-3" />
                                        {step.duration || step.timestamp}
                                    </div>
                                )}
                            </div>
                            {state === 'active' && step.details && (
                                <div className="mt-3 p-3 rounded-lg bg-ops-black border border-ops-border">
                                    <code className="text-[11px] text-ops-cyan font-mono">{step.details}</code>
                                </div>
                            )}
                        </div>
                    </div>
                );
            })}
        </div>
    );
}
