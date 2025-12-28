import { motion } from 'framer-motion';
import {
    Target, Server, Shield, Activity, Zap, Globe, Database, TrendingUp
} from 'lucide-react';

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
            style={{ padding: '2rem', display: 'flex', flexDirection: 'column', gap: '2rem' }}
        >
            {}
            <div
                className="panel"
                style={{ padding: '1.5rem', borderLeft: '4px solid #3b82f6' }}
            >
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div
                        style={{
                            width: '2.5rem',
                            height: '2.5rem',
                            borderRadius: '50%',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            backgroundColor: 'rgba(59, 130, 246, 0.2)'
                        }}
                    >
                        {isExitMode
                            ? <Server style={{ width: '1.25rem', height: '1.25rem', color: '#3b82f6' }} />
                            : <Shield style={{ width: '1.25rem', height: '1.25rem', color: '#3b82f6' }} />
                        }
                    </div>
                    <div style={{ flex: 1 }}>
                        <h2 style={{ fontSize: '1.125rem', fontWeight: 'bold', color: 'white', margin: 0 }}>
                            {isExitMode ? '🔍 Exit-Side PCAP Analysis' : '🔍 Entry-Side PCAP Analysis'}
                        </h2>
                        <p style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '0.25rem' }}>
                            {isExitMode
                                ? 'Predicting probable guard nodes from exit traffic patterns'
                                : 'Analyzing entry-side traffic to identify guard node'}
                        </p>
                    </div>
                    <span
                        style={{
                            padding: '0.25rem 0.75rem',
                            fontSize: '0.75rem',
                            fontWeight: '600',
                            borderRadius: '9999px',
                            backgroundColor: 'rgba(59, 130, 246, 0.2)',
                            color: '#3b82f6'
                        }}
                    >
                        AUTO-DETECTED
                    </span>
                </div>
            </div>

            {}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '2rem' }}>

                {}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

                    {}
                    {isExitMode && probableGuards.length > 0 && (
                        <div className="panel" style={{ padding: '1.25rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                                <Target style={{ width: '1rem', height: '1rem', color: '#10b981' }} />
                                <h3 style={{ fontSize: '0.75rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>Probable Guard Nodes</h3>
                            </div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                                {probableGuards.slice(0, 3).map((guard, idx) => (
                                    <div
                                        key={idx}
                                        style={{
                                            padding: '0.75rem',
                                            borderRadius: '0.5rem',
                                            backgroundColor: idx === 0 ? 'rgba(16, 185, 129, 0.1)' : 'rgba(255,255,255,0.03)',
                                            border: idx === 0 ? '1px solid rgba(16, 185, 129, 0.3)' : 'none'
                                        }}
                                    >
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                            <span style={{ fontSize: '1.5rem' }}>{guard.flag || '🌐'}</span>
                                            <div style={{ flex: 1 }}>
                                                <p style={{ fontFamily: 'monospace', fontSize: '0.875rem', color: 'white', margin: 0 }}>{guard.ip}</p>
                                                <p style={{ fontSize: '0.625rem', color: '#9ca3af', margin: 0 }}>{guard.country} • {guard.isp}</p>
                                            </div>
                                            <div style={{ textAlign: 'right' }}>
                                                <p style={{ fontSize: '1.125rem', fontWeight: 'bold', color: '#10b981', margin: 0 }}>{(guard.guard_probability * 100).toFixed(0)}%</p>
                                                {guard.in_consensus && (
                                                    <span style={{ fontSize: '0.5rem', padding: '0.125rem 0.375rem', backgroundColor: 'rgba(16, 185, 129, 0.2)', color: '#10b981', borderRadius: '0.25rem' }}>TOR CONSENSUS</span>
                                                )}
                                            </div>
                                        </div>
                                        {guard.reason && (
                                            <p style={{ fontSize: '0.5625rem', color: '#f59e0b', marginTop: '0.5rem' }}>🔬 {guard.reason}</p>
                                        )}
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {}
                    {!isExitMode && results.top_finding && (
                        <div className="panel" style={{ padding: '1.25rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                                <Target style={{ width: '1rem', height: '1rem', color: '#10b981' }} />
                                <h3 style={{ fontSize: '0.75rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>Inferred Guard Node</h3>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                <span style={{ fontSize: '2rem' }}>{results.top_finding.flag || '🌐'}</span>
                                <div>
                                    <p style={{ fontFamily: 'monospace', fontSize: '1.125rem', color: 'white', margin: 0 }}>{results.top_finding.ip}</p>
                                    <p style={{ fontSize: '0.75rem', color: '#9ca3af', margin: 0 }}>{results.top_finding.country}</p>
                                    <p style={{ fontSize: '0.75rem', color: '#6b7280', margin: 0 }}>{results.top_finding.isp}</p>
                                </div>
                            </div>
                            <div style={{ marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid rgba(255,255,255,0.1)' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <span style={{ fontSize: '0.75rem', color: '#9ca3af' }}>Confidence</span>
                                    <span style={{ fontSize: '1.125rem', fontWeight: 'bold', color: '#10b981' }}>
                                        {(results.top_finding.confidence_score * 100).toFixed(0)}%
                                    </span>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

                    {}
                    <div className="panel" style={{ padding: '1.25rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                            <Server style={{ width: '1rem', height: '1rem', color: '#3b82f6' }} />
                            <h3 style={{ fontSize: '0.75rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>
                                {isExitMode ? 'Detected Exit Nodes' : 'Predicted Exit Nodes'}
                            </h3>
                        </div>
                        {topExits.length > 0 ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                                {topExits.slice(0, 3).map((exit, idx) => (
                                    <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem', backgroundColor: 'rgba(255,255,255,0.03)', borderRadius: '0.25rem' }}>
                                        <span style={{ fontSize: '1.125rem' }}>{exit.flag || '🌐'}</span>
                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <p style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'white', margin: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{exit.ip}</p>
                                            <p style={{ fontSize: '0.625rem', color: '#9ca3af', margin: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{exit.isp}</p>
                                        </div>
                                        <div style={{ textAlign: 'right' }}>
                                            <p style={{ fontSize: '0.75rem', color: '#3b82f6', fontWeight: '600', margin: 0 }}>{exit.packet_count} pkts</p>
                                            {exit.in_consensus && <span style={{ fontSize: '0.5rem', color: '#10b981' }}>📡</span>}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <p style={{ fontSize: '0.875rem', color: '#9ca3af' }}>No exit nodes detected</p>
                        )}
                    </div>

                    {}
                    {isExitMode && (
                        <div className="panel" style={{ padding: '1.25rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                                <Zap style={{ width: '1rem', height: '1rem', color: '#f59e0b' }} />
                                <h3 style={{ fontSize: '0.75rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>Flow Fingerprint</h3>
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem' }}>
                                <div style={{ backgroundColor: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '0.25rem' }}>
                                    <p style={{ fontSize: '0.75rem', color: '#9ca3af', margin: 0 }}>Burst Entropy</p>
                                    <p style={{ fontFamily: 'monospace', fontSize: '0.875rem', color: 'white', margin: 0 }}>{fingerprint.burst_entropy?.toFixed(3) || 'N/A'}</p>
                                </div>
                                <div style={{ backgroundColor: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '0.25rem' }}>
                                    <p style={{ fontSize: '0.75rem', color: '#9ca3af', margin: 0 }}>Micro-gap Avg</p>
                                    <p style={{ fontFamily: 'monospace', fontSize: '0.875rem', color: 'white', margin: 0 }}>{fingerprint.micro_gap_avg ? `${(fingerprint.micro_gap_avg * 1000).toFixed(2)}ms` : 'N/A'}</p>
                                </div>
                                <div style={{ backgroundColor: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '0.25rem' }}>
                                    <p style={{ fontSize: '0.75rem', color: '#9ca3af', margin: 0 }}>Size Var Slope</p>
                                    <p style={{ fontFamily: 'monospace', fontSize: '0.875rem', color: 'white', margin: 0 }}>{fingerprint.size_variance_slope?.toFixed(2) || 'N/A'}</p>
                                </div>
                                <div style={{ backgroundColor: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '0.25rem' }}>
                                    <p style={{ fontSize: '0.75rem', color: '#9ca3af', margin: 0 }}>Circuit Lifetime</p>
                                    <p style={{ fontFamily: 'monospace', fontSize: '0.875rem', color: 'white', margin: 0 }}>{fingerprint.circuit_lifetime ? `${fingerprint.circuit_lifetime.toFixed(2)}s` : 'N/A'}</p>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

                    {}
                    <div className="panel" style={{ padding: '1.25rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                            <Activity style={{ width: '1rem', height: '1rem', color: '#67d4ff' }} />
                            <h3 style={{ fontSize: '0.75rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>Traffic Profile</h3>
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ fontSize: '0.75rem', color: '#9ca3af' }}>Total Packets</span>
                                <span style={{ fontFamily: 'monospace', color: 'white' }}>{flowMetadata.total_packets?.toLocaleString() || 0}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ fontSize: '0.75rem', color: '#9ca3af' }}>Total Bytes</span>
                                <span style={{ fontFamily: 'monospace', color: 'white' }}>{flowMetadata.total_bytes ? `${(flowMetadata.total_bytes / 1024).toFixed(1)} KB` : '0 KB'}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ fontSize: '0.75rem', color: '#9ca3af' }}>Flow Count</span>
                                <span style={{ fontFamily: 'monospace', color: 'white' }}>{flowMetadata.total_flows || 0}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ fontSize: '0.75rem', color: '#9ca3af' }}>CDN Filtered</span>
                                <span style={{ fontFamily: 'monospace', color: '#f59e0b' }}>{flowMetadata.cdn_filtered || 0}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ fontSize: '0.75rem', color: '#9ca3af' }}>Tor Cell Ratio</span>
                                <span style={{ fontFamily: 'monospace', color: '#10b981' }}>{flowMetadata.tor_cell_ratio ? `${(flowMetadata.tor_cell_ratio * 100).toFixed(1)}%` : 'N/A'}</span>
                            </div>
                        </div>
                    </div>

                    {}
                    <div
                        className="panel"
                        style={{
                            padding: '1.25rem',
                            background: 'linear-gradient(to bottom right, rgba(59, 130, 246, 0.1), transparent)'
                        }}
                    >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                            <Database style={{ width: '1rem', height: '1rem', color: '#3b82f6' }} />
                            <h3 style={{ fontSize: '0.75rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>Analysis Summary</h3>
                        </div>
                        <p style={{ fontSize: '0.75rem', color: '#6b7280', lineHeight: '1.5', margin: 0 }}>
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
