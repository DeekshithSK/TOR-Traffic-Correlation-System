import { Check, Upload, Activity, BarChart3 } from 'lucide-react';

const STEPS = [
    { id: 'upload', label: 'Upload Evidence', icon: Upload },
    { id: 'processing', label: 'Analyze', icon: Activity },
    { id: 'results', label: 'Review Findings', icon: BarChart3 }
];

export default function StepWizard({ currentStep }) {
    const stepIndex = STEPS.findIndex(s => s.id === currentStep);

    return (
        <div className="w-full max-w-2xl mx-auto mb-12">
            <div className="flex items-center justify-between relative">
                {}
                <div className="absolute top-5 left-0 right-0 h-0.5 bg-ops-border" />

                {}
                <div
                    className="absolute top-5 left-0 h-0.5 bg-ops-cyan transition-all duration-500 ease-out"
                    style={{ width: `${(stepIndex / (STEPS.length - 1)) * 100}%` }}
                />

                {STEPS.map((step, index) => {
                    const Icon = step.icon;
                    const isCompleted = index < stepIndex;
                    const isActive = index === stepIndex;

                    return (
                        <div key={step.id} className="relative z-10 flex flex-col items-center">
                            {}
                            <div
                                className={`
                  w-10 h-10 rounded-full flex items-center justify-center
                  transition-all duration-300 border-2
                  ${isCompleted
                                        ? 'bg-secure border-secure text-white'
                                        : isActive
                                            ? 'bg-ops-cyan border-ops-cyan text-ops-black shadow-glow-cyan'
                                            : 'bg-panel-dark border-ops-border text-text-tertiary'
                                    }
                `}
                            >
                                {isCompleted ? (
                                    <Check className="w-5 h-5" />
                                ) : (
                                    <Icon className="w-5 h-5" />
                                )}
                            </div>

                            {}
                            <span
                                className={`
                  mt-3 text-xs font-semibold uppercase tracking-wider
                  transition-colors duration-300
                  ${isActive ? 'text-ops-cyan' : isCompleted ? 'text-secure' : 'text-text-muted'}
                `}
                            >
                                {step.label}
                            </span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
