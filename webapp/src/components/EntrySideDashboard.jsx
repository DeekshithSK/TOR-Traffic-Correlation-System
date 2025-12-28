import { motion } from 'framer-motion';
import {
    Target, Shield, Activity, Globe, TrendingUp, Server, MapPin, Wifi
} from 'lucide-react';

export default function EntrySideDashboard({ results, caseInfo }) {
    const actualCaseId = caseInfo?.case_id || 'CASE-UNKNOWN';

    const topFinding = results.top_finding || {};
    const correlation = results.correlation || {};
    const details = results.details || {};

    const confidenceScores = details.scores || [];
    const labels = details.labels || [];

    const predictedExits = correlation.probable_exits || [];

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}
        >
            {}
            <div
                className="panel"
                style={{
                    padding: '1.5rem',
                    borderLeft: '4px solid #10b981',
                    background: 'linear-gradient(to right, rgba(16, 185, 129, 0.1), transparent)'
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
                            backgroundColor: 'rgba(16, 185, 129, 0.2)'
                        }}
                    >
                        <Shield style={{ width: '1.5rem', height: '1.5rem', color: '#10b981' }} />
                    </div>
                    <div style={{ flex: 1 }}>
                        <h2 style={{ fontSize: '1.25rem', fontWeight: 'bold', color: 'white', margin: 0 }}>
                            🛡️ Entry-Side PCAP Analysis
                        </h2>
                        <p style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '0.25rem' }}>
                            Guard node correlation from client-side traffic patterns
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
                                            analysis_mode: 'entry_only',
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
                                backgroundColor: 'rgba(16, 185, 129, 0.2)',
                                color: '#10b981'
                            }}
                        >
                            ENTRY-SIDE
                        </span>
                    </div>
                </div>
            </div>

            {}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>

                {}
                <div className="panel" style={{ padding: '1.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem' }}>
                        <Target style={{ width: '1.25rem', height: '1.25rem', color: '#10b981' }} />
                        <h3 style={{ fontSize: '0.875rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>
                            Identified Guard Nodes
                        </h3>
                    </div>

                    {labels.length > 0 ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                            {labels.slice(0, 5).map((ip, idx) => (
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
                                        <span style={{ fontSize: '1.25rem' }}>{idx === 0 && topFinding.flag ? topFinding.flag : '🌐'}</span>
                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <p style={{
                                                fontFamily: 'monospace',
                                                fontSize: idx === 0 ? '1.125rem' : '0.875rem',
                                                color: 'white',
                                                fontWeight: idx === 0 ? 'bold' : '600',
                                                margin: 0
                                            }}>
                                                {ip}
                                            </p>
                                            {idx === 0 && topFinding.country && (
                                                <p style={{ fontSize: '0.75rem', color: '#9ca3af', margin: 0 }}>
                                                    {topFinding.country}
                                                </p>
                                            )}
                                        </div>
                                        <div style={{ textAlign: 'right' }}>
                                            <p style={{
                                                fontSize: idx === 0 ? '1.25rem' : '1rem',
                                                fontWeight: 'bold',
                                                color: idx === 0 ? '#10b981' : '#9ca3af',
                                                margin: 0
                                            }}>
                                                {confidenceScores[idx] ? `${(confidenceScores[idx] * 100).toFixed(0)}%` : 'N/A'}
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            ))}

                            {}
                            {topFinding.origin_ip && (
                                <div style={{
                                    marginTop: '0.5rem',
                                    padding: '0.75rem',
                                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                                    borderRadius: '0.5rem',
                                    border: '1px solid rgba(59, 130, 246, 0.3)'
                                }}>
                                    <p style={{ fontSize: '0.625rem', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>
                                        🖥️ Client IP (Connected to Guard)
                                    </p>
                                    <p style={{
                                        fontFamily: 'monospace',
                                        fontSize: '1rem',
                                        color: '#3b82f6',
                                        fontWeight: '600',
                                        margin: '0.25rem 0 0 0'
                                    }}>
                                        {topFinding.origin_ip}
                                    </p>
                                </div>
                            )}
                        </div>
                    ) : topFinding.ip ? (
                        <div>
                            {}
                            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
                                <span style={{ fontSize: '2rem' }}>{topFinding.flag || '🌐'}</span>
                                <div>
                                    <p style={{
                                        fontFamily: 'monospace',
                                        fontSize: '1.25rem',
                                        color: 'white',
                                        fontWeight: 'bold',
                                        margin: 0
                                    }}>
                                        {topFinding.ip}
                                    </p>
                                    <p style={{ fontSize: '0.875rem', color: '#9ca3af', margin: 0 }}>
                                        {topFinding.country || 'Unknown Location'}
                                    </p>
                                </div>
                            </div>

                            {topFinding.origin_ip && (
                                <div style={{
                                    padding: '0.75rem',
                                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                                    borderRadius: '0.5rem',
                                    border: '1px solid rgba(59, 130, 246, 0.3)'
                                }}>
                                    <p style={{ fontSize: '0.625rem', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>
                                        🖥️ Client IP
                                    </p>
                                    <p style={{
                                        fontFamily: 'monospace',
                                        fontSize: '1rem',
                                        color: '#3b82f6',
                                        fontWeight: '600',
                                        margin: '0.25rem 0 0 0'
                                    }}>
                                        {topFinding.origin_ip}
                                    </p>
                                </div>
                            )}
                        </div>
                    ) : (
                        <div style={{ textAlign: 'center', padding: '2rem', color: '#6b7280' }}>
                            <Shield style={{ width: '3rem', height: '3rem', margin: '0 auto 1rem', opacity: 0.5 }} />
                            <p>No guard nodes identified</p>
                        </div>
                    )}
                </div>

                {}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

                    {}
                    <div className="panel" style={{ padding: '1.25rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                            <Activity style={{ width: '1rem', height: '1rem', color: '#3b82f6' }} />
                            <h3 style={{ fontSize: '0.75rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>
                                Correlated Sessions
                            </h3>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem' }}>
                            <span style={{ fontSize: '2.5rem', fontWeight: 'bold', color: 'white' }}>
                                {topFinding.correlated_sessions || labels.length || 0}
                            </span>
                            <span style={{ fontSize: '0.875rem', color: '#9ca3af' }}>sessions matched</span>
                        </div>

                        {}
                        {confidenceScores.length > 1 && (
                            <div style={{ marginTop: '1rem' }}>
                                <p style={{ fontSize: '0.625rem', color: '#6b7280', marginBottom: '0.5rem' }}>Score Distribution</p>
                                <div style={{ display: 'flex', gap: '2px', height: '2rem' }}>
                                    {confidenceScores.slice(0, 10).map((score, idx) => (
                                        <div
                                            key={idx}
                                            style={{
                                                flex: 1,
                                                backgroundColor: idx === 0 ? '#10b981' : 'rgba(59, 130, 246, 0.5)',
                                                borderRadius: '2px',
                                                height: `${Math.max(20, score * 100)}%`
                                            }}
                                            title={`${labels[idx]}: ${(score * 100).toFixed(1)}%`}
                                        />
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>

                    {}
                    <div className="panel" style={{ padding: '1.25rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                            <Server style={{ width: '1rem', height: '1rem', color: '#8b5cf6' }} />
                            <h3 style={{ fontSize: '0.75rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>
                                Predicted Exit Nodes
                            </h3>
                        </div>
                        {predictedExits.length > 0 ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                                {predictedExits.slice(0, 3).map((exit, idx) => (
                                    <div key={idx} style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '0.5rem',
                                        padding: '0.5rem',
                                        backgroundColor: 'rgba(255,255,255,0.03)',
                                        borderRadius: '0.25rem'
                                    }}>
                                        <span>{exit.flag || '🌐'}</span>
                                        <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'white', flex: 1 }}>
                                            {exit.ip}
                                        </span>
                                        <span style={{ fontSize: '0.75rem', color: '#8b5cf6' }}>
                                            {(exit.probability * 100).toFixed(0)}%
                                        </span>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <p style={{ fontSize: '0.75rem', color: '#6b7280' }}>
                                Exit nodes inferred from Tor path estimation
                            </p>
                        )}
                    </div>

                    {}
                    <div
                        className="panel"
                        style={{
                            padding: '1rem',
                            background: 'linear-gradient(to bottom right, rgba(16, 185, 129, 0.1), transparent)'
                        }}
                    >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                            <TrendingUp style={{ width: '1rem', height: '1rem', color: '#10b981' }} />
                            <h4 style={{ fontSize: '0.75rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>
                                Analysis Summary
                            </h4>
                        </div>
                        <p style={{ fontSize: '0.75rem', color: '#6b7280', lineHeight: '1.5', margin: 0 }}>
                            Analyzed entry-side traffic patterns and correlated {labels.length || 0} sessions.
                            {topFinding.ip && ` Identified ${topFinding.ip} as the most probable Tor guard relay.`}
                        </p>
                    </div>
                </div>
            </div>
        </motion.div>
    );
}
