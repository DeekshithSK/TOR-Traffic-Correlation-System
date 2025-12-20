import { motion } from 'framer-motion';
import {
    Target, Server, Shield, Activity, Zap, Globe, Database, TrendingUp
} from 'lucide-react';

/**
 * Single-Side PCAP Analysis Dashboard
 * Displays results when only one PCAP (entry OR exit) is analyzed
 */
export default function SingleSideDashboard({ results }) {
    const isExitMode = results.analysis_mode === 'exit_only';
    const correlation = results.correlation || {};
    const flowMetadata = results.flow_metadata || {};
    const probableGuards = correlation.probable_guards || [];
    const topExits = correlation.top_exit_nodes || [];
    const fingerprint = flowMetadata.fingerprint || {};

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6 py-8 px-6"
        >
            {/* Mode Header */}
            <div className="panel p-4 border-l-4 border-intel">
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-full bg-intel/20 flex items-center justify-center">
                        {isExitMode ? <Server className="w-5 h-5 text-intel" /> : <Shield className="w-5 h-5 text-intel" />}
                    </div>
                    <div>
                        <h2 className="text-lg font-bold text-white">
                            {isExitMode ? '🔍 Exit-Side PCAP Analysis' : '🔍 Entry-Side PCAP Analysis'}
                        </h2>
                        <p className="text-xs text-text-muted">
                            {isExitMode
                                ? 'Predicting probable guard nodes from exit traffic patterns'
                                : 'Analyzing entry-side traffic to identify guard node'}
                        </p>
                    </div>
                    <span className="ml-auto px-3 py-1 bg-intel/20 text-intel text-xs font-semibold rounded-full">
                        AUTO-DETECTED
                    </span>
                </div>
            </div>

            {/* Main Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '2rem' }}>

                {/* LEFT: Primary Finding */}
                <div className="space-y-6">

                    {/* Probable Guard Nodes (Exit Mode) */}
                    {isExitMode && probableGuards.length > 0 && (
                        <div className="panel p-5">
                            <div className="flex items-center gap-2 mb-4">
                                <Target className="w-4 h-4 text-secure" />
                                <h3 className="text-xs font-bold text-text-tertiary uppercase">Probable Guard Nodes</h3>
                            </div>
                            <div className="space-y-3">
                                {probableGuards.slice(0, 3).map((guard, idx) => (
                                    <div key={idx} className={`p-3 rounded-lg ${idx === 0 ? 'bg-secure/10 border border-secure/30' : 'bg-surface-elevated/50'}`}>
                                        <div className="flex items-center gap-3">
                                            <span className="text-2xl">{guard.flag || '🌐'}</span>
                                            <div className="flex-1">
                                                <p className="font-mono text-sm text-white">{guard.ip}</p>
                                                <p className="text-[10px] text-text-muted">{guard.country} • {guard.isp}</p>
                                            </div>
                                            <div className="text-right">
                                                <p className="text-lg font-bold text-secure">{(guard.guard_probability * 100).toFixed(0)}%</p>
                                                {guard.in_consensus && (
                                                    <span className="text-[8px] px-1.5 py-0.5 bg-secure/20 text-secure rounded">TOR CONSENSUS</span>
                                                )}
                                            </div>
                                        </div>
                                        {guard.reason && (
                                            <p className="text-[9px] text-amber-400 mt-2">🔬 {guard.reason}</p>
                                        )}
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Inferred Guard (Entry Mode) */}
                    {!isExitMode && results.top_finding && (
                        <div className="panel p-5">
                            <div className="flex items-center gap-2 mb-4">
                                <Target className="w-4 h-4 text-secure" />
                                <h3 className="text-xs font-bold text-text-tertiary uppercase">Inferred Guard Node</h3>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className="text-3xl">{results.top_finding.flag || '🌐'}</span>
                                <div>
                                    <p className="font-mono text-lg text-white">{results.top_finding.ip}</p>
                                    <p className="text-xs text-text-muted">{results.top_finding.country}</p>
                                    <p className="text-xs text-text-secondary">{results.top_finding.isp}</p>
                                </div>
                            </div>
                            <div className="mt-4 pt-3 border-t border-ops-border">
                                <div className="flex justify-between items-center">
                                    <span className="text-xs text-text-tertiary">Confidence</span>
                                    <span className="text-lg font-bold text-secure">
                                        {(results.top_finding.confidence_score * 100).toFixed(0)}%
                                    </span>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {/* CENTER: Exit Nodes / Flow Stats */}
                <div className="space-y-6">

                    {/* Detected Exit Nodes */}
                    <div className="panel p-5">
                        <div className="flex items-center gap-2 mb-4">
                            <Server className="w-4 h-4 text-intel" />
                            <h3 className="text-xs font-bold text-text-tertiary uppercase">
                                {isExitMode ? 'Detected Exit Nodes' : 'Predicted Exit Nodes'}
                            </h3>
                        </div>
                        {topExits.length > 0 ? (
                            <div className="space-y-2">
                                {topExits.slice(0, 3).map((exit, idx) => (
                                    <div key={idx} className="flex items-center gap-2 p-2 bg-surface-elevated/30 rounded">
                                        <span className="text-lg">{exit.flag || '🌐'}</span>
                                        <div className="flex-1 min-w-0">
                                            <p className="font-mono text-xs text-white truncate">{exit.ip}</p>
                                            <p className="text-[10px] text-text-muted truncate">{exit.isp}</p>
                                        </div>
                                        <div className="text-right">
                                            <p className="text-xs text-intel font-semibold">{exit.packet_count} pkts</p>
                                            {exit.in_consensus && <span className="text-[8px] text-secure">📡</span>}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <p className="text-sm text-text-muted">No exit nodes detected</p>
                        )}
                    </div>

                    {/* Flow Fingerprint */}
                    {isExitMode && (
                        <div className="panel p-5">
                            <div className="flex items-center gap-2 mb-4">
                                <Zap className="w-4 h-4 text-amber-400" />
                                <h3 className="text-xs font-bold text-text-tertiary uppercase">Flow Fingerprint</h3>
                            </div>
                            <div className="grid grid-cols-2 gap-3 text-xs">
                                <div className="bg-surface-elevated/30 p-2 rounded">
                                    <p className="text-text-muted">Burst Entropy</p>
                                    <p className="font-mono text-white">{fingerprint.burst_entropy?.toFixed(3) || 'N/A'}</p>
                                </div>
                                <div className="bg-surface-elevated/30 p-2 rounded">
                                    <p className="text-text-muted">Micro-gap Avg</p>
                                    <p className="font-mono text-white">{fingerprint.micro_gap_avg ? `${(fingerprint.micro_gap_avg * 1000).toFixed(2)}ms` : 'N/A'}</p>
                                </div>
                                <div className="bg-surface-elevated/30 p-2 rounded">
                                    <p className="text-text-muted">Size Var Slope</p>
                                    <p className="font-mono text-white">{fingerprint.size_variance_slope?.toFixed(2) || 'N/A'}</p>
                                </div>
                                <div className="bg-surface-elevated/30 p-2 rounded">
                                    <p className="text-text-muted">Circuit Lifetime</p>
                                    <p className="font-mono text-white">{fingerprint.circuit_lifetime ? `${fingerprint.circuit_lifetime.toFixed(2)}s` : 'N/A'}</p>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {/* RIGHT: Traffic Profile */}
                <div className="space-y-6">

                    {/* Traffic Profile */}
                    <div className="panel p-5">
                        <div className="flex items-center gap-2 mb-4">
                            <Activity className="w-4 h-4 text-ops-cyan" />
                            <h3 className="text-xs font-bold text-text-tertiary uppercase">Traffic Profile</h3>
                        </div>
                        <div className="space-y-3">
                            <div className="flex justify-between items-center">
                                <span className="text-xs text-text-muted">Total Packets</span>
                                <span className="font-mono text-white">{flowMetadata.total_packets?.toLocaleString() || 0}</span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="text-xs text-text-muted">Total Bytes</span>
                                <span className="font-mono text-white">{flowMetadata.total_bytes ? `${(flowMetadata.total_bytes / 1024).toFixed(1)} KB` : '0 KB'}</span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="text-xs text-text-muted">Flow Count</span>
                                <span className="font-mono text-white">{flowMetadata.total_flows || 0}</span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="text-xs text-text-muted">CDN Filtered</span>
                                <span className="font-mono text-amber-400">{flowMetadata.cdn_filtered || 0}</span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="text-xs text-text-muted">Tor Cell Ratio</span>
                                <span className="font-mono text-secure">{flowMetadata.tor_cell_ratio ? `${(flowMetadata.tor_cell_ratio * 100).toFixed(1)}%` : 'N/A'}</span>
                            </div>
                        </div>
                    </div>

                    {/* Analysis Summary */}
                    <div className="panel p-5 bg-gradient-to-br from-intel/10 to-transparent">
                        <div className="flex items-center gap-2 mb-3">
                            <Database className="w-4 h-4 text-intel" />
                            <h3 className="text-xs font-bold text-text-tertiary uppercase">Analysis Summary</h3>
                        </div>
                        <p className="text-xs text-text-secondary leading-relaxed">
                            {isExitMode
                                ? `Analyzed ${flowMetadata.total_flows || 0} flows from exit-side capture. Predicted ${probableGuards.length} probable guard nodes using flow fingerprinting and Tor consensus correlation.`
                                : `Analyzed entry-side traffic patterns. Identified probable guard node with ${results.top_finding?.confidence_level || 'Medium'} confidence.`
                            }
                        </p>
                    </div>
                </div>
            </div>
        </motion.div>
    );
}
