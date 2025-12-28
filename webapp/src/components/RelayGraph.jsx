import { useState } from 'react';
import Plot from 'react-plotly.js';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Monitor, Server, Cloud, Globe, Shield,
    AlertTriangle, Info, X, ChevronRight
} from 'lucide-react';


const COUNTRY_FLAGS = {
    'US': '🇺🇸', 'DE': '🇩🇪', 'NL': '🇳🇱', 'FR': '🇫🇷', 'GB': '🇬🇧',
    'CA': '🇨🇦', 'CH': '🇨🇭', 'SE': '🇸🇪', 'FI': '🇫🇮', 'RO': '🇷🇴',
    'RU': '🇷🇺', 'UA': '🇺🇦', 'LU': '🇱🇺', 'AT': '🇦🇹', 'CZ': '🇨🇿',
    'PL': '🇵🇱', 'AU': '🇦🇺', 'JP': '🇯🇵', 'SG': '🇸🇬', 'IN': '🇮🇳',
};

const getFlag = (country) => {
    if (!country) return '🌐';
    const code = country.toUpperCase().slice(0, 2);
    return COUNTRY_FLAGS[code] || '🌐';
};

export default function RelayGraph({
    pathData,
    guardConfidence = 0,
    clientIP = 'Local Client',
    guardGeo = {}  // Geolocation data: { country, city, flag, isp }
}) {
    const [selectedNode, setSelectedNode] = useState(null);
    const [showModal, setShowModal] = useState(false);

    if (!pathData || !pathData.graph) {
        return (
            <div className="w-full p-6 rounded-xl bg-ops-panel border border-ops-border">
                <div className="flex items-center gap-2 text-text-tertiary">
                    <AlertTriangle className="w-5 h-5" />
                    <span>No path inference data available</span>
                </div>
            </div>
        );
    }

    const { graph, guard, exit_candidates = [], metadata = {} } = pathData;

    const buildSankeyData = () => {
        const nodeLabels = ['Client\n(Observed)', `Guard Relay\n${guard?.ip || 'Unknown'}`, 'Tor Network\n(Hidden)',];
        const nodeColors = [
            'rgba(96, 165, 250, 0.8)',  // Client - blue
            'rgba(34, 211, 238, 0.9)',  // Guard - cyan (highlighted)
            'rgba(148, 163, 184, 0.5)', // Tor Core - gray dashed
        ];

        const topExits = exit_candidates.slice(0, 5);
        topExits.forEach((exit, i) => {
            const prob = (exit.probability * 100).toFixed(1);
            nodeLabels.push(`Exit ${i + 1}\n${exit.ip || 'Unknown'}\n(${prob}%)`);
            const opacity = Math.max(0.3, Math.min(0.9, exit.probability * 3));
            nodeColors.push(`rgba(251, 191, 36, ${opacity})`); // Amber
        });

        const source = [];
        const target = [];
        const value = [];
        const linkColors = [];

        source.push(0);
        target.push(1);
        value.push(100);
        linkColors.push('rgba(34, 211, 238, 0.6)'); // Cyan

        source.push(1);
        target.push(2);
        value.push(100);
        linkColors.push('rgba(148, 163, 184, 0.4)'); // Gray

        topExits.forEach((exit, i) => {
            source.push(2);
            target.push(3 + i);
            value.push(Math.max(5, exit.probability * 100));
            const opacity = Math.max(0.2, Math.min(0.6, exit.probability * 2));
            linkColors.push(`rgba(251, 191, 36, ${opacity})`);
        });

        return {
            node: {
                label: nodeLabels,
                color: nodeColors,
                pad: 30,
                thickness: 20,
                line: {
                    color: 'rgba(255, 255, 255, 0.3)',
                    width: 1
                }
            },
            link: {
                source: source,
                target: target,
                value: value,
                color: linkColors
            }
        };
    };

    const sankeyData = buildSankeyData();

    const handleNodeClick = (data) => {
        if (data.points && data.points[0]) {
            const pointIndex = data.points[0].pointNumber;
            if (pointIndex >= 3) {
                const exitIndex = pointIndex - 3;
                if (exit_candidates[exitIndex]) {
                    setSelectedNode(exit_candidates[exitIndex]);
                    setShowModal(true);
                }
            }
        }
    };

    return (
        <div className="w-full space-y-4">
            {}
            <div className="p-4 rounded-xl bg-ops-panel border border-ops-border">
                <div className="flex items-center justify-between mb-4">
                    <h4 className="text-[10px] font-bold text-text-tertiary uppercase tracking-widest flex items-center gap-2">
                        <Shield className="w-4 h-4 text-ops-cyan" />
                        Reconstructed Tor Path
                    </h4>
                    <div className="flex items-center gap-2">
                        <span className="px-2 py-1 text-[10px] font-mono bg-amber-500/20 text-amber-400 rounded border border-amber-500/30">
                            PROBABILISTIC
                        </span>
                    </div>
                </div>

                {}
                <div className="mb-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                    <div className="text-xs text-amber-200">
                        <strong>Probabilistic Estimation:</strong> Exit node candidates are estimated using Tor's
                        bandwidth-weighted selection algorithm. This is NOT exact circuit reconstruction—middle
                        relays are hidden by design and exit nodes shown are statistical probabilities only.
                    </div>
                </div>

                {}
                <div className="bg-ops-bg rounded-lg p-2 border border-ops-border">
                    <Plot
                        data={[{
                            type: 'sankey',
                            orientation: 'h',
                            ...sankeyData
                        }]}
                        layout={{
                            font: {
                                family: 'JetBrains Mono, monospace',
                                size: 10,
                                color: '#94a3b8'
                            },
                            paper_bgcolor: 'transparent',
                            plot_bgcolor: 'transparent',
                            margin: { l: 20, r: 20, t: 20, b: 20 },
                            height: 300
                        }}
                        config={{
                            displayModeBar: false,
                            staticPlot: false
                        }}
                        onClick={handleNodeClick}
                        style={{ width: '100%' }}
                    />
                </div>
            </div>

            {}
            <div className="p-4 rounded-xl bg-ops-panel border border-ops-border">
                <h5 className="text-[10px] font-bold text-text-tertiary uppercase tracking-widest mb-3">
                    Path Legend
                </h5>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                    <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full bg-blue-400" />
                        <span className="text-text-secondary">Client (Observed)</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.6)]" />
                        <span className="text-text-secondary">Guard (Inferred)</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded border border-dashed border-slate-400" />
                        <span className="text-text-secondary">Tor Core (Hidden)</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full bg-amber-400 opacity-70" />
                        <span className="text-text-secondary">Exit (Probabilistic)</span>
                    </div>
                </div>

                {}
                <div className="mt-4 pt-4 border-t border-ops-border grid grid-cols-3 gap-4 text-xs">
                    <div className="flex items-center gap-2">
                        <div className="w-8 h-0.5 bg-cyan-400" />
                        <span className="text-text-tertiary">Traffic Inferred</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="w-8 h-0.5 border-t-2 border-dashed border-slate-400" />
                        <span className="text-text-tertiary">Inferred Boundary</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="w-8 h-0.5 border-t-2 border-dotted border-amber-400" />
                        <span className="text-text-tertiary">Probabilistic</span>
                    </div>
                </div>
            </div>

            {}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {}
                <div className="p-4 rounded-xl bg-ops-panel border-2 border-ops-cyan shadow-glow-cyan">
                    <div className="flex items-center gap-2 mb-3">
                        <Server className="w-5 h-5 text-ops-cyan" />
                        <span className="text-xs font-bold text-ops-cyan uppercase">Guard Relay</span>
                    </div>
                    <div className="space-y-2 text-xs">
                        <div className="flex justify-between">
                            <span className="text-text-tertiary">IP Address</span>
                            <span className="font-mono text-white">{guard?.ip || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-text-tertiary">Nickname</span>
                            <span className="font-mono text-white">{guard?.nickname || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-text-tertiary">Country</span>
                            <span className="text-white">{guardGeo?.flag || getFlag(guard?.country)} {guardGeo?.country || guard?.country || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-text-tertiary">Confidence</span>
                            <span className={`font-bold ${guard?.confidence >= 0.7 ? 'text-green-400' : guard?.confidence >= 0.5 ? 'text-amber-400' : 'text-red-400'}`}>
                                {((guard?.confidence || 0) * 100).toFixed(1)}%
                            </span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-text-tertiary">In Consensus</span>
                            <span className={guard?.in_consensus ? 'text-green-400' : 'text-amber-400'}>
                                {guard?.in_consensus ? '✓ Yes' : '⚠ No'}
                            </span>
                        </div>
                    </div>
                </div>



                {}
                {exit_candidates.length > 0 && (
                    <div className="p-4 rounded-xl bg-ops-panel border border-amber-500/50">
                        <div className="flex items-center gap-2 mb-3">
                            <Globe className="w-5 h-5 text-amber-400" />
                            <span className="text-xs font-bold text-amber-400 uppercase">Top Exit Candidate</span>
                        </div>
                        <div className="space-y-2 text-xs">
                            <div className="flex justify-between">
                                <span className="text-text-tertiary">IP Address</span>
                                <span className="font-mono text-white">{exit_candidates[0]?.ip || 'Unknown'}</span>
                            </div>
                            <div className="flex justify-between">
                                <span className="text-text-tertiary">Nickname</span>
                                <span className="font-mono text-white">{exit_candidates[0]?.nickname || 'Unknown'}</span>
                            </div>
                            <div className="flex justify-between">
                                <span className="text-text-tertiary">Probability</span>
                                <span className="font-bold text-amber-400">
                                    {((exit_candidates[0]?.probability || 0) * 100).toFixed(1)}%
                                </span>
                            </div>
                            <button
                                onClick={() => {
                                    setSelectedNode(exit_candidates[0]);
                                    setShowModal(true);
                                }}
                                className="mt-2 w-full px-3 py-2 rounded bg-amber-500/20 text-amber-400 hover:bg-amber-500/30 transition-colors flex items-center justify-center gap-1"
                            >
                                View All Exits <ChevronRight className="w-4 h-4" />
                            </button>
                        </div>
                    </div>
                )}
            </div>

            {}
            <AnimatePresence>
                {showModal && selectedNode && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70"
                        onClick={() => setShowModal(false)}
                    >
                        <motion.div
                            initial={{ scale: 0.9, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                            exit={{ scale: 0.9, opacity: 0 }}
                            className="w-full max-w-2xl bg-ops-panel border border-ops-border rounded-xl p-6 shadow-2xl"
                            onClick={(e) => e.stopPropagation()}
                        >
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                    <Globe className="w-5 h-5 text-amber-400" />
                                    Exit Relay Probability Breakdown
                                </h3>
                                <button
                                    onClick={() => setShowModal(false)}
                                    className="p-2 rounded-lg hover:bg-ops-border transition-colors"
                                >
                                    <X className="w-5 h-5 text-text-tertiary" />
                                </button>
                            </div>

                            {}
                            <div className="mb-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs text-amber-200">
                                <AlertTriangle className="w-4 h-4 inline mr-2" />
                                These are <strong>probabilistic estimates</strong> based on Tor's bandwidth-weighted selection algorithm.
                            </div>

                            {}
                            <div className="overflow-hidden rounded-lg border border-ops-border">
                                <table className="w-full text-xs">
                                    <thead className="bg-ops-bg">
                                        <tr>
                                            <th className="px-4 py-3 text-left text-text-tertiary font-medium">Rank</th>
                                            <th className="px-4 py-3 text-left text-text-tertiary font-medium">IP Address</th>
                                            <th className="px-4 py-3 text-left text-text-tertiary font-medium">Nickname</th>
                                            <th className="px-4 py-3 text-left text-text-tertiary font-medium">Country</th>
                                            <th className="px-4 py-3 text-right text-text-tertiary font-medium">Probability</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {exit_candidates.slice(0, 10).map((exit, i) => (
                                            <tr
                                                key={exit.fingerprint || i}
                                                className={`border-t border-ops-border ${i === 0 ? 'bg-amber-500/10' : 'hover:bg-ops-border/50'}`}
                                            >
                                                <td className="px-4 py-3 text-text-secondary">{i + 1}</td>
                                                <td className="px-4 py-3 font-mono text-white">{exit.ip}</td>
                                                <td className="px-4 py-3 text-text-secondary">{exit.nickname}</td>
                                                <td className="px-4 py-3 text-text-secondary">
                                                    {getFlag(exit.country)} {exit.country || 'Unknown'}
                                                </td>
                                                <td className="px-4 py-3 text-right">
                                                    <span className="font-bold text-amber-400">
                                                        {(exit.probability * 100).toFixed(2)}%
                                                    </span>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>

                            {}
                            <div className="mt-4 pt-4 border-t border-ops-border text-xs text-text-tertiary">
                                <div className="flex justify-between">
                                    <span>Sample Count: {metadata?.sample_count || 'N/A'}</span>
                                    <span>Total Candidates: {exit_candidates.length}</span>
                                </div>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
