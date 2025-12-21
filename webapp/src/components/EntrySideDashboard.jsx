import { motion } from 'framer-motion';
import {
    Target, Shield, Activity, Globe, TrendingUp, Server, MapPin, Wifi
} from 'lucide-react';

/**
 * Entry-Side PCAP Analysis Dashboard
 * Displays results when an entry-side (guard) PCAP is analyzed
 * 
 * Primary focus: Inferred Guard Node
 */
export default function EntrySideDashboard({ results }) {
    const topFinding = results.top_finding || {};
    const correlation = results.correlation || {};
    const details = results.details || {};

    // Get confidence scores for chart
    const confidenceScores = details.scores || [];
    const labels = details.labels || [];

    // Get predicted exit nodes from consensus-based prediction
    const predictedExits = correlation.probable_exits || [];

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
                                            case_id: results.case_id || 'CASE-DEMO',
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
                                        a.download = `Entry_Side_Report_${results.case_id || 'DEMO'}.pdf`;
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

            {/* Main Grid - 2 Columns */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>

                {/* LEFT: Primary Finding - Guard Node */}
                <div className="panel" style={{ padding: '1.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem' }}>
                        <Target style={{ width: '1.25rem', height: '1.25rem', color: '#10b981' }} />
                        <h3 style={{ fontSize: '0.875rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>
                            Inferred Guard Node
                        </h3>
                    </div>

                    {topFinding.ip ? (
                        <div>
                            {/* Main IP Display */}
                            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem' }}>
                                <span style={{ fontSize: '2.5rem' }}>{topFinding.flag || '🌐'}</span>
                                <div>
                                    <p style={{
                                        fontFamily: 'monospace',
                                        fontSize: '1.5rem',
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

                            {/* Metadata Grid */}
                            <div style={{
                                display: 'grid',
                                gridTemplateColumns: 'repeat(2, 1fr)',
                                gap: '1rem',
                                marginBottom: '1.5rem'
                            }}>
                                <div style={{ backgroundColor: 'rgba(255,255,255,0.03)', padding: '0.75rem', borderRadius: '0.5rem' }}>
                                    <p style={{ fontSize: '0.625rem', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>ISP / ASN</p>
                                    <p style={{ fontSize: '0.875rem', color: 'white', margin: '0.25rem 0 0 0' }}>
                                        {topFinding.isp || 'Unknown'}
                                    </p>
                                </div>
                                <div style={{ backgroundColor: 'rgba(255,255,255,0.03)', padding: '0.75rem', borderRadius: '0.5rem' }}>
                                    <p style={{ fontSize: '0.625rem', color: '#9ca3af', textTransform: 'uppercase', margin: 0 }}>Relay Role</p>
                                    <p style={{ fontSize: '0.875rem', color: '#10b981', fontWeight: '600', margin: '0.25rem 0 0 0' }}>
                                        Guard Relay
                                    </p>
                                </div>
                            </div>

                            {/* Client IP Display */}
                            {topFinding.origin_ip && (
                                <div style={{
                                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                                    padding: '0.75rem',
                                    borderRadius: '0.5rem',
                                    marginBottom: '1rem',
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

                            {/* Confidence Score */}
                            <div style={{
                                padding: '1rem',
                                borderRadius: '0.5rem',
                                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                                border: '1px solid rgba(16, 185, 129, 0.3)'
                            }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <div>
                                        <p style={{ fontSize: '0.75rem', color: '#9ca3af', margin: 0 }}>Correlation Confidence</p>
                                        <p style={{ fontSize: '0.625rem', color: '#6b7280', margin: '0.25rem 0 0 0' }}>
                                            {topFinding.confidence_level || 'Medium'} confidence match
                                        </p>
                                    </div>
                                    <span style={{
                                        fontSize: '2rem',
                                        fontWeight: 'bold',
                                        color: '#10b981'
                                    }}>
                                        {topFinding.confidence_score
                                            ? `${(topFinding.confidence_score * 100).toFixed(0)}`
                                            : topFinding.guard_confidence
                                                ? `${(topFinding.guard_confidence * 100).toFixed(0)}`
                                                : 'N/A'}
                                    </span>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div style={{ textAlign: 'center', padding: '2rem', color: '#6b7280' }}>
                            <Shield style={{ width: '3rem', height: '3rem', margin: '0 auto 1rem', opacity: 0.5 }} />
                            <p>No guard node detected</p>
                        </div>
                    )}
                </div>

                {/* RIGHT: Session & Traffic Stats */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

                    {/* Correlated Sessions */}
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

                        {/* Confidence Distribution */}
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

                    {/* Predicted Exit Nodes */}
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

                    {/* Analysis Summary */}
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
