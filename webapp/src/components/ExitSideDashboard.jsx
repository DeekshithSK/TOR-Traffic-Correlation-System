import { motion } from 'framer-motion';
import {
    Server, Target, Activity, Zap, Database, Globe, AlertTriangle, CheckCircle
} from 'lucide-react';

/**
 * Exit-Side PCAP Analysis Dashboard
 * Displays results when an exit-side PCAP is analyzed
 * 
 * Primary focus: Detected Exit Nodes & Probable Guards
 */
export default function ExitSideDashboard({ results, caseInfo }) {
    // Use caseInfo.case_id for actual case identifier (e.g., CASE-1766468634)
    const actualCaseId = caseInfo?.case_id || 'CASE-UNKNOWN';

    const correlation = results.correlation || {};
    const flowMetadata = results.flow_metadata || {};
    const probableGuards = correlation.probable_guards || [];
    const topExits = correlation.top_exit_nodes || [];
    const fingerprint = flowMetadata.fingerprint || {};

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}
        >
            {/* Header Banner */}
            <div
                className="panel"
                style={{
                    padding: '1.5rem',
                    borderLeft: '4px solid #3b82f6',
                    background: 'linear-gradient(to right, rgba(59, 130, 246, 0.1), transparent)'
                }}
            >
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div
                        style={{
                            width: '3rem',
                            height: '3rem',
                            borderRadius: '50%',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            backgroundColor: 'rgba(59, 130, 246, 0.2)'
                        }}
                    >
                        <Server style={{ width: '1.5rem', height: '1.5rem', color: '#3b82f6' }} />
                    </div>
                    <div style={{ flex: 1 }}>
                        <h2 style={{ fontSize: '1.25rem', fontWeight: 'bold', color: 'white', margin: 0 }}>
                            🔍 Exit-Side PCAP Analysis
                        </h2>
                        <p style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '0.25rem' }}>
                            Predicting probable guard nodes from exit traffic patterns
                        </p>
                    </div>
                    <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                        <button
                            onClick={async () => {
                                try {
                                    const response = await fetch('http://localhost:8000/api/export-dashboard-report', {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({
                                            case_id: actualCaseId,
                                            analysis_mode: 'exit_only',
                                            results: results,
                                            pcap_hash: results.pcap_hash || null
                                        })
                                    });
                                    if (response.ok) {
                                        const blob = await response.blob();
                                        const url = window.URL.createObjectURL(blob);
                                        const a = document.createElement('a');
                                        a.href = url;
                                        a.download = `${actualCaseId}.pdf`;
                                        a.click();
                                        window.URL.revokeObjectURL(url);
                                    } else {
                                        alert('Report generation failed');
                                    }
                                } catch (err) {
                                    console.error('Export error:', err);
                                    alert('Failed to export report');
                                }
                            }}
                            style={{
                                padding: '0.625rem 1.5rem',
                                fontSize: '0.875rem',
                                fontWeight: '600',
                                borderRadius: '0.5rem',
                                backgroundColor: '#3b82f6',
                                color: 'white',
                                border: 'none',
                                cursor: 'pointer',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.5rem',
                                boxShadow: '0 2px 4px rgba(59, 130, 246, 0.3)'
                            }}
                        >
                            📄 Export Report
                        </button>
                        <span
                            style={{
                                padding: '0.375rem 1rem',
                                fontSize: '0.75rem',
                                fontWeight: '600',
                                borderRadius: '9999px',
                                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                                color: '#3b82f6'
                            }}
                        >
                            EXIT-SIDE
                        </span>
                    </div>
                </div>
            </div>

            {/* Main Grid - 3 Columns: Exit Nodes (larger), Guard Nodes (smaller), Traffic Profile */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 1fr', gap: '2rem' }}>

                {/* LEFT: Verified Tor Exit Nodes (NOW BIGGER) */}
                <div className="panel" style={{ padding: '1.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem' }}>
                        <Server style={{ width: '1.25rem', height: '1.25rem', color: '#3b82f6' }} />
                        <h3 style={{ fontSize: '0.875rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>
                            Verified Tor Exit Nodes
                        </h3>
                    </div>
                    {topExits.length > 0 ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                            {topExits.slice(0, 6).map((exit, idx) => (
                                <div key={idx} style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '0.75rem',
                                    padding: '0.75rem',
                                    borderRadius: '0.5rem',
                                    backgroundColor: idx === 0 ? 'rgba(59, 130, 246, 0.1)' : 'rgba(255,255,255,0.03)',
                                    border: idx === 0 ? '1px solid rgba(59, 130, 246, 0.3)' : 'none'
                                }}>
                                    <span style={{ fontSize: '1.5rem' }}>{exit.flag || '🌐'}</span>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <p style={{
                                            fontFamily: 'monospace',
                                            fontSize: '0.875rem',
                                            color: 'white',
                                            margin: 0,
                                            fontWeight: '600'
                                        }}>
                                            {exit.ip}
                                        </p>
                                        <p style={{ fontSize: '0.75rem', color: '#9ca3af', margin: 0 }}>
                                            {exit.country} • {(exit.isp || '').substring(0, 20)}
                                        </p>
                                    </div>
                                    <div style={{ textAlign: 'right' }}>
                                        <p style={{ fontSize: '0.875rem', color: '#3b82f6', fontWeight: '600', margin: 0 }}>
                                            {exit.packet_count} pkts
                                        </p>
                                        {exit.in_consensus && (
                                            <CheckCircle style={{ width: '0.875rem', height: '0.875rem', color: '#10b981' }} />
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <p style={{ fontSize: '0.875rem', color: '#9ca3af', textAlign: 'center', padding: '2rem' }}>
                            No verified Tor exits detected
                        </p>
                    )}
                </div>

                {/* CENTER: Probable Guard Nodes (NOW SMALLER, NO %) */}
                <div className="panel" style={{ padding: '1rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                        <Target style={{ width: '1rem', height: '1rem', color: '#10b981' }} />
                        <h3 style={{ fontSize: '0.7rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>
                            Probable Guard Nodes
                        </h3>
                    </div>

                    {probableGuards.length > 0 ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            {probableGuards.slice(0, 4).map((guard, idx) => (
                                <div
                                    key={idx}
                                    style={{
                                        padding: '0.5rem',
                                        borderRadius: '0.375rem',
                                        backgroundColor: idx === 0 ? 'rgba(16, 185, 129, 0.1)' : 'rgba(255,255,255,0.03)',
                                        border: idx === 0 ? '1px solid rgba(16, 185, 129, 0.3)' : 'none'
                                    }}
                                >
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <span style={{ fontSize: '1.125rem' }}>{guard.flag || '🌐'}</span>
                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <p style={{
                                                fontFamily: 'monospace',
                                                fontSize: '0.75rem',
                                                color: 'white',
                                                margin: 0,
                                                overflow: 'hidden',
                                                textOverflow: 'ellipsis',
                                                whiteSpace: 'nowrap'
                                            }}>
                                                {guard.ip}
                                            </p>
                                            <p style={{ fontSize: '0.5625rem', color: '#9ca3af', margin: 0 }}>
                                                {guard.country}
                                            </p>
                                        </div>
                                        {guard.in_consensus && (
                                            <span style={{
                                                fontSize: '0.5rem',
                                                padding: '0.125rem 0.25rem',
                                                backgroundColor: 'rgba(16, 185, 129, 0.2)',
                                                color: '#10b981',
                                                borderRadius: '0.25rem'
                                            }}>
                                                TOR
                                            </span>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div style={{ textAlign: 'center', padding: '1rem', color: '#6b7280' }}>
                            <AlertTriangle style={{ width: '1.5rem', height: '1.5rem', margin: '0 auto 0.5rem', opacity: 0.5 }} />
                            <p style={{ fontSize: '0.625rem' }}>No guard nodes predicted</p>
                        </div>
                    )}
                </div>

                {/* RIGHT: Flow Fingerprint & Traffic Profile */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    {/* Flow Fingerprint */}
                    <div className="panel" style={{ padding: '1rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                            <Zap style={{ width: '1rem', height: '1rem', color: '#f59e0b' }} />
                            <h3 style={{ fontSize: '0.7rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>
                                Flow Fingerprint
                            </h3>
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.5rem' }}>
                            <div style={{ backgroundColor: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '0.25rem' }}>
                                <p style={{ fontSize: '0.5625rem', color: '#9ca3af', margin: 0 }}>Burst Entropy</p>
                                <p style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'white', margin: 0 }}>
                                    {fingerprint.burst_entropy?.toFixed(3) || 'N/A'}
                                </p>
                            </div>
                            <div style={{ backgroundColor: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '0.25rem' }}>
                                <p style={{ fontSize: '0.5625rem', color: '#9ca3af', margin: 0 }}>Micro-gap Avg</p>
                                <p style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'white', margin: 0 }}>
                                    {fingerprint.micro_gap_avg ? `${(fingerprint.micro_gap_avg * 1000).toFixed(2)}ms` : 'N/A'}
                                </p>
                            </div>
                            <div style={{ backgroundColor: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '0.25rem' }}>
                                <p style={{ fontSize: '0.5625rem', color: '#9ca3af', margin: 0 }}>Size Var Slope</p>
                                <p style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'white', margin: 0 }}>
                                    {fingerprint.size_variance_slope?.toFixed(2) || 'N/A'}
                                </p>
                            </div>
                            <div style={{ backgroundColor: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '0.25rem' }}>
                                <p style={{ fontSize: '0.5625rem', color: '#9ca3af', margin: 0 }}>Circuit Lifetime</p>
                                <p style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'white', margin: 0 }}>
                                    {fingerprint.circuit_lifetime ? `${fingerprint.circuit_lifetime.toFixed(2)}s` : 'N/A'}
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Traffic Profile - in same column as Flow Fingerprint */}
                    <div className="panel" style={{ padding: '1rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                            <Activity style={{ width: '1rem', height: '1rem', color: '#67d4ff' }} />
                            <h3 style={{ fontSize: '0.7rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>
                                Traffic Profile
                            </h3>
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ fontSize: '0.625rem', color: '#9ca3af' }}>Total Packets</span>
                                <span style={{ fontFamily: 'monospace', color: 'white', fontSize: '0.75rem' }}>
                                    {flowMetadata.total_packets?.toLocaleString() || 0}
                                </span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ fontSize: '0.625rem', color: '#9ca3af' }}>Total Bytes</span>
                                <span style={{ fontFamily: 'monospace', color: 'white', fontSize: '0.75rem' }}>
                                    {flowMetadata.total_bytes ? `${(flowMetadata.total_bytes / 1024).toFixed(1)} KB` : '0 KB'}
                                </span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ fontSize: '0.625rem', color: '#9ca3af' }}>Flow Count</span>
                                <span style={{ fontFamily: 'monospace', color: 'white', fontSize: '0.75rem' }}>
                                    {flowMetadata.total_flows || 0}
                                </span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ fontSize: '0.625rem', color: '#9ca3af' }}>Unique Exit IPs</span>
                                <span style={{ fontFamily: 'monospace', color: '#10b981', fontSize: '0.75rem' }}>
                                    {flowMetadata.unique_ips || topExits.length || 0}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Analysis Summary */}
            <div
                className="panel"
                style={{
                    padding: '1rem',
                    background: 'linear-gradient(to bottom right, rgba(59, 130, 246, 0.1), transparent)'
                }}
            >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <Database style={{ width: '1rem', height: '1rem', color: '#3b82f6' }} />
                    <h3 style={{ fontSize: '0.7rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>
                        Analysis Summary
                    </h3>
                </div>
                <p style={{ fontSize: '0.75rem', color: '#6b7280', lineHeight: '1.5', margin: 0 }}>
                    Analyzed {flowMetadata.total_flows || 0} flows from exit-side capture.
                    {topExits.length > 0 && ` Detected ${topExits.length} verified Tor exit nodes.`}
                    {probableGuards.length > 0 && ` Predicted ${probableGuards.length} probable guard nodes using flow fingerprinting.`}
                </p>
            </div>
        </motion.div>
    );
}

