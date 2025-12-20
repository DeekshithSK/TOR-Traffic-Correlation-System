import { motion } from 'framer-motion';
import {
    Target, Server, Shield, Activity, CheckCircle, Link, TrendingUp, Database, AlertCircle
} from 'lucide-react';

/**
 * Dual-Side PCAP Analysis Dashboard
 * Displays results when both entry + exit PCAPs are analyzed
 */
export default function DualSideDashboard({ results }) {
    const correlation = results.correlation || {};
    const topFinding = results.top_finding || {};
    const topExits = correlation.top_exit_nodes || [];
    const ipLeads = results.ip_leads || [];

    const isConfirmed = correlation.exit_confirmation || correlation.mode === 'guard+exit_confirmed';
    const matchScore = correlation.exit_boosted_score || correlation.exit_direct_score || 0;

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-8 py-8 px-6"
        >
            {/* Mode Header */}
            <div className={`panel p-6 border-l-4 ${isConfirmed ? 'border-secure' : 'border-intel'}`}>
                <div className="flex items-center gap-4">
                    <div className={`w-12 h-12 rounded-full flex items-center justify-center ${isConfirmed ? 'bg-secure/20' : 'bg-intel/20'}`}>
                        <Link className={`w-6 h-6 ${isConfirmed ? 'text-secure' : 'text-intel'}`} />
                    </div>
                    <div className="flex-1">
                        <h2 className="text-xl font-bold text-white">
                            🔗 Dual-Side PCAP Correlation
                        </h2>
                        <p className="text-sm text-text-muted mt-1">
                            {isConfirmed
                                ? 'Entry and exit traffic correlated successfully'
                                : 'Analyzing correlation between entry and exit captures'}
                        </p>
                    </div>
                    <span className={`px-4 py-2 text-sm font-semibold rounded-full ${isConfirmed ? 'bg-secure/20 text-secure' : 'bg-intel/20 text-intel'}`}>
                        {isConfirmed ? 'CONFIRMED' : 'ANALYZING'}
                    </span>
                </div>
            </div>

            {/* Primary Findings Row - 2 Columns */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '2rem' }}>

                {/* Confirmed Guard Node */}
                <div className="panel p-6 hover:border-secure/50 transition-colors">
                    <div className="flex items-center gap-2 mb-5">
                        <Target className="w-5 h-5 text-secure" />
                        <h3 className="text-sm font-bold text-text-tertiary uppercase tracking-wider">
                            {isConfirmed ? 'Confirmed Guard Node' : 'Inferred Guard Node'}
                        </h3>
                    </div>
                    <div className="flex items-center gap-4 mb-4">
                        <span className="text-5xl">{topFinding.flag || '🌐'}</span>
                        <div>
                            <p className="font-mono text-xl text-white font-semibold">{topFinding.ip || 'Unknown'}</p>
                            <p className="text-sm text-text-muted mt-1">{topFinding.country || 'Unknown'}</p>
                            <p className="text-sm text-text-secondary">{topFinding.isp || 'Unknown ISP'}</p>
                        </div>
                    </div>
                    <div className="mt-5 pt-4 border-t border-ops-border flex items-center justify-between">
                        <span className="text-sm text-text-tertiary">Confidence</span>
                        <div className="flex items-center gap-3">
                            <span className={`text-2xl font-bold ${topFinding.confidence_level === 'High' ? 'text-secure' : 'text-intel'}`}>
                                {((topFinding.confidence_score || 0) * 100).toFixed(0)}%
                            </span>
                            <span className={`text-xs px-3 py-1 rounded-full ${topFinding.confidence_level === 'High' ? 'bg-secure/20 text-secure' : 'bg-intel/20 text-intel'}`}>
                                {topFinding.confidence_level || 'Medium'}
                            </span>
                        </div>
                    </div>
                </div>

                {/* Top Exit Nodes */}
                <div className="panel p-6 hover:border-intel/50 transition-colors">
                    <div className="flex items-center gap-2 mb-5">
                        <Server className="w-5 h-5 text-intel" />
                        <h3 className="text-sm font-bold text-text-tertiary uppercase tracking-wider">Top Exit Nodes</h3>
                    </div>
                    {topExits.length > 0 ? (
                        <div className="space-y-3">
                            {topExits.slice(0, 3).map((exit, idx) => (
                                <div key={idx} className={`flex items-center gap-3 p-3 rounded-lg transition-colors ${idx === 0 ? 'bg-intel/10 border border-intel/30' : 'bg-surface-elevated/30 hover:bg-surface-elevated/50'}`}>
                                    <span className="text-2xl">{exit.flag || '🌐'}</span>
                                    <div className="flex-1 min-w-0">
                                        <p className="font-mono text-sm text-white truncate">{exit.ip}</p>
                                        <p className="text-xs text-text-muted truncate">{exit.country}</p>
                                    </div>
                                    {exit.score && (
                                        <span className="text-sm font-mono font-semibold text-intel">{(exit.score * 100).toFixed(0)}%</span>
                                    )}
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="flex items-center justify-center h-32 text-text-muted">
                            <p className="text-sm">Processing exit data...</p>
                        </div>
                    )}
                </div>
            </div>

            {/* IP Leads Row - Full Width */}
            <div className="panel p-6">
                <div className="flex items-center gap-2 mb-5">
                    <Database className="w-5 h-5 text-amber-400" />
                    <h3 className="text-sm font-bold text-text-tertiary uppercase tracking-wider">IP Leads</h3>
                    {ipLeads.length > 0 && (
                        <span className="ml-auto text-xs px-2 py-1 bg-surface-elevated rounded text-text-muted">{ipLeads.length} candidates</span>
                    )}
                </div>
                {ipLeads.length > 0 ? (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="text-text-tertiary text-left border-b-2 border-ops-border">
                                    <th className="pb-3 font-semibold">IP Address</th>
                                    <th className="pb-3 font-semibold">Country</th>
                                    <th className="pb-3 font-semibold">ISP</th>
                                    <th className="pb-3 font-semibold text-right">Score</th>
                                    <th className="pb-3 font-semibold text-right">Flows</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-ops-border/30">
                                {ipLeads.slice(0, 5).map((lead, idx) => (
                                    <tr key={idx} className={`transition-colors ${idx === 0 ? 'bg-secure/5' : 'hover:bg-surface-elevated/30'}`}>
                                        <td className="py-3 font-mono text-white">{lead.ip}</td>
                                        <td className="py-3">
                                            <span className="text-xl mr-2">{lead.flag || '🌐'}</span>
                                            <span className="text-text-muted">{lead.country}</span>
                                        </td>
                                        <td className="py-3 text-text-secondary truncate max-w-[180px]">{lead.isp}</td>
                                        <td className="py-3 text-right font-semibold text-secure">{((lead.final || 0) * 100).toFixed(0)}%</td>
                                        <td className="py-3 text-right text-text-muted">{lead.flow_count}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <div className="flex flex-col items-center justify-center py-12 text-text-muted">
                        <AlertCircle className="w-10 h-10 mb-3 opacity-40" />
                        <p className="text-sm">No IP leads generated</p>
                    </div>
                )}
            </div>

            {/* Analysis Summary */}
            <div className="panel p-5 bg-gradient-to-r from-secure/5 via-intel/5 to-transparent border-t-2 border-ops-cyan/30">
                <div className="flex items-center gap-4">
                    <TrendingUp className="w-6 h-6 text-ops-cyan" />
                    <div>
                        <p className="text-sm text-text-secondary">
                            <span className="text-white font-semibold">✓ Dual-Side Analysis Complete:</span>{' '}
                            {isConfirmed
                                ? `Successfully correlated entry traffic (Guard: ${topFinding.ip}) with exit traffic. ${correlation.session_count || 1} sessions verified.`
                                : `Analyzed guard node with ${topFinding.confidence_level || 'Medium'} confidence. Exit correlation ${matchScore > 0 ? 'partially matched' : 'pending'}.`
                            }
                        </p>
                    </div>
                </div>
            </div>
        </motion.div>
    );
}
