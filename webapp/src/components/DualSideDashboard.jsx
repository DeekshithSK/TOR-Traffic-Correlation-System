import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Target, Server, Shield, Activity, CheckCircle, Link, TrendingUp, Database, AlertCircle, X, User, Info
} from 'lucide-react';

export default function DualSideDashboard({ results, caseInfo }) {
    const [selectedMatch, setSelectedMatch] = useState(null);

    const actualCaseId = caseInfo?.case_id || 'CASE-UNKNOWN';

    const correlation = results.correlation || {};
    const topFinding = results.top_finding || {};
    const topExits = correlation.top_exit_nodes || [];
    const guardExitPairs = correlation.guard_exit_pairs || [];
    const ipLeads = results.ip_leads || [];

    const isConfirmed = correlation.exit_confirmation || correlation.mode === 'guard+exit_confirmed';
    const matchScore = correlation.exit_boosted_score || correlation.exit_direct_score || 0;

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            style={{ padding: '2rem', display: 'flex', flexDirection: 'column', gap: '2rem' }}
        >
            {}
            <div
                className={`panel border-l-4 ${isConfirmed ? 'border-secure' : 'border-intel'}`}
                style={{ padding: '1.5rem' }}
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
                            backgroundColor: isConfirmed ? 'rgba(16, 185, 129, 0.2)' : 'rgba(59, 130, 246, 0.2)'
                        }}
                    >
                        <Link style={{ width: '1.5rem', height: '1.5rem', color: isConfirmed ? '#10b981' : '#3b82f6' }} />
                    </div>
                    <div style={{ flex: 1 }}>
                        <h2 style={{ fontSize: '1.25rem', fontWeight: 'bold', color: 'white', margin: 0 }}>
                            🔗 Dual-Side PCAP Correlation
                        </h2>
                        <p style={{ fontSize: '0.875rem', color: '#9ca3af', marginTop: '0.25rem' }}>
                            {isConfirmed
                                ? 'Entry and exit traffic correlated successfully'
                                : 'Analyzing correlation between entry and exit captures'}
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
                                            analysis_mode: 'guard_exit',
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
                                padding: '0.5rem 1rem',
                                fontSize: '0.875rem',
                                fontWeight: '600',
                                borderRadius: '9999px',
                                backgroundColor: isConfirmed ? 'rgba(16, 185, 129, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                                color: isConfirmed ? '#10b981' : '#3b82f6'
                            }}
                        >
                            {isConfirmed ? 'CONFIRMED' : 'ANALYZING'}
                        </span>
                    </div>
                </div>
            </div>


            {}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 200px 1fr', gap: '1.5rem', alignItems: 'stretch' }}>

                {}
                <div className="panel" style={{ padding: '1.5rem', position: 'relative', zIndex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem' }}>
                        <Target style={{ width: '1.25rem', height: '1.25rem', color: '#10b981' }} />
                        <h3 style={{ fontSize: '0.875rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', margin: 0 }}>
                            {isConfirmed ? 'Confirmed Guard Node' : 'Inferred Guard Node'}
                        </h3>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
                        <span style={{ fontSize: '3rem' }}>{topFinding.flag || '🌐'}</span>
                        <div>
                            <p style={{ fontFamily: 'monospace', fontSize: '1.25rem', color: 'white', margin: 0, fontWeight: '600' }}>{topFinding.ip || 'Unknown'}</p>
                            <p style={{ fontSize: '0.875rem', color: '#9ca3af', margin: '0.25rem 0 0 0' }}>{topFinding.country || 'Unknown'}</p>
                            <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>{topFinding.isp || 'Unknown ISP'}</p>
                        </div>
                    </div>

                    {}
                    {topFinding.origin_ip && (
                        <div style={{
                            marginTop: '1rem',
                            padding: '0.75rem',
                            backgroundColor: 'rgba(245, 158, 11, 0.1)',
                            borderRadius: '0.5rem',
                            border: '1px solid rgba(245, 158, 11, 0.3)'
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                                <span style={{ fontSize: '1rem' }}>🔍</span>
                                <span style={{ fontSize: '0.75rem', fontWeight: 'bold', color: '#f59e0b', textTransform: 'uppercase' }}>Origin IP Detected</span>
                            </div>
                            <p style={{ fontFamily: 'monospace', fontSize: '1.125rem', color: '#f59e0b', margin: 0, fontWeight: '600' }}>
                                {topFinding.origin_ip}
                            </p>
                            <p style={{ fontSize: '0.625rem', color: '#9ca3af', margin: '0.25rem 0 0 0' }}>
                                Client connected to guard node
                            </p>
                        </div>
                    )}

                    {}
                    <div style={{ marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid rgba(255,255,255,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <span style={{ fontSize: '0.875rem', color: '#9ca3af' }}>Final Confidence</span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                            <span style={{
                                fontSize: '0.75rem',
                                padding: '0.25rem 0.75rem',
                                borderRadius: '9999px',
                                backgroundColor: (topFinding.confidence_score >= 0.90) ? 'rgba(16, 185, 129, 0.2)' : (topFinding.confidence_score >= 0.50) ? 'rgba(59, 130, 246, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                                color: (topFinding.confidence_score >= 0.90) ? '#10b981' : (topFinding.confidence_score >= 0.50) ? '#3b82f6' : '#ef4444'
                            }}>
                                {(topFinding.confidence_score >= 0.90) ? 'High (≥90%)' : (topFinding.confidence_score >= 0.50) ? 'Medium (≥50%)' : 'Low (<50%)'}
                            </span>
                        </div>
                    </div>

                </div>




                {}
                <div style={{ position: 'relative', width: '200px', height: '300px', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 0 }}>
                    <svg
                        width="300"
                        height="300"
                        viewBox="0 0 100 100"
                        preserveAspectRatio="none"
                        style={{ position: 'absolute', left: '-50px', width: '300px', height: '100%', zIndex: 1, overflow: 'visible' }}
                    >
                        <defs>
                            <linearGradient id="wireGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                                <stop offset="0%" stopColor="#3b82f6" />
                                <stop offset="100%" stopColor="#60a5fa" />
                            </linearGradient>
                            <filter id="glow" x="-50%" y="-500%" width="200%" height="1100%">
                                <feGaussianBlur stdDeviation="1" result="coloredBlur" />
                                <feMerge>
                                    <feMergeNode in="coloredBlur" />
                                    <feMergeNode in="SourceGraphic" />
                                </feMerge>
                            </filter>
                        </defs>

                        {}
                        <path
                            d="M 0 60 C 40 60, 50 30, 100 30"
                            stroke="url(#wireGradient)"
                            strokeWidth="1.5"
                            fill="none"
                            filter="url(#glow)"
                            strokeLinecap="round"
                            opacity="0.9"
                            vectorEffect="non-scaling-stroke"
                        >
                            <animate attributeName="opacity" values="0.5;1;0.5" dur="4s" repeatCount="indefinite" />
                        </path>

                        {}
                        <path
                            d="M 0 60 C 40 60, 50 50, 100 50"
                            stroke="url(#wireGradient)"
                            strokeWidth="1.5"
                            fill="none"
                            filter="url(#glow)"
                            strokeLinecap="round"
                            opacity="0.9"
                            vectorEffect="non-scaling-stroke"
                        >
                            <animate attributeName="opacity" values="0.5;1;0.5" dur="4s" repeatCount="indefinite" begin="0.3s" />
                        </path>

                        {}
                        <path
                            d="M 0 60 C 40 60, 50 70, 100 70"
                            stroke="url(#wireGradient)"
                            strokeWidth="1.5"
                            fill="none"
                            filter="url(#glow)"
                            strokeLinecap="round"
                            opacity="0.9"
                            vectorEffect="non-scaling-stroke"
                        >
                            <animate attributeName="opacity" values="0.5;1;0.5" dur="4s" repeatCount="indefinite" begin="0.6s" />
                        </path>

                        {}
                        <path
                            d="M 0 60 C 40 60, 50 90, 100 90"
                            stroke="url(#wireGradient)"
                            strokeWidth="1.5"
                            fill="none"
                            filter="url(#glow)"
                            strokeLinecap="round"
                            opacity="0.9"
                            vectorEffect="non-scaling-stroke"
                        >
                            <animate attributeName="opacity" values="0.5;1;0.5" dur="4s" repeatCount="indefinite" begin="0.9s" />
                        </path>
                    </svg>
                </div>

                {}
                <div className="panel" style={{ padding: '1.5rem', position: 'relative', zIndex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem' }}>
                        <Server style={{ width: '1.25rem', height: '1.25rem', color: '#3b82f6' }} />
                        <h3 style={{ fontSize: '0.875rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', margin: 0 }}>Top Exit Nodes</h3>
                    </div>
                    {topExits.length > 0 ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                            {}
                            {[...topExits.slice(0, 3)].sort((a, b) => {
                                const idxA = topExits.indexOf(a);
                                const idxB = topExits.indexOf(b);
                                if (idxA === 0) return 1;
                                if (idxB === 0) return -1;
                                return 0;
                            }).map((exit, idx) => (
                                <div
                                    key={idx}
                                    style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '0.75rem',
                                        padding: '0.75rem',
                                        borderRadius: '0.5rem',
                                        backgroundColor: 'rgba(255,255,255,0.03)'
                                    }}
                                >
                                    <span style={{ fontSize: '1.5rem' }}>{exit.flag || '🌐'}</span>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <p style={{ fontFamily: 'monospace', fontSize: '0.875rem', color: 'white', margin: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{exit.ip}</p>
                                        <p style={{ fontSize: '0.75rem', color: '#9ca3af', margin: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{exit.country}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '8rem', color: '#9ca3af' }}>
                            <p style={{ fontSize: '0.875rem' }}>Processing exit data...</p>
                        </div>
                    )}
                </div>
            </div>

            {}
            <div className="panel" style={{ padding: '1.5rem', position: 'relative' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem' }}>
                    <Link style={{ width: '1.25rem', height: '1.25rem', color: '#10b981' }} />
                    <h3 style={{ fontSize: '0.875rem', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', margin: 0 }}>Top Guard-Exit Matches</h3>
                    <span style={{ marginLeft: 'auto', fontSize: '0.625rem', color: '#6b7280' }}>Click for details</span>
                </div>
                {guardExitPairs.length > 0 ? (
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
                        {guardExitPairs.slice(0, 4).map((pair, idx) => (
                            <div
                                key={`${pair.guard_ip}-${pair.exit_ip}-${idx}`}
                                onClick={() => setSelectedMatch(pair)}
                                style={{
                                    padding: '1rem',
                                    borderRadius: '0.75rem',
                                    backgroundColor: idx === 0 ? 'rgba(16, 185, 129, 0.1)' : 'rgba(255,255,255,0.03)',
                                    border: idx === 0 ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(255,255,255,0.05)',
                                    cursor: 'pointer',
                                    transition: 'all 0.2s ease'
                                }}
                                onMouseEnter={(e) => e.currentTarget.style.transform = 'translateY(-2px)'}
                                onMouseLeave={(e) => e.currentTarget.style.transform = 'translateY(0)'}
                            >
                                {}
                                <div style={{ marginBottom: '0.5rem' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                                        <Shield style={{ width: '0.875rem', height: '0.875rem', color: '#3b82f6' }} />
                                        <span style={{ fontSize: '0.625rem', color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Guard</span>
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <span style={{ fontSize: '1.25rem' }}>{pair.guard_flag || topFinding.flag || '🌐'}</span>
                                        <p style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'white', margin: 0, fontWeight: '600' }}>
                                            {pair.guard_ip}
                                        </p>
                                    </div>
                                </div>

                                {}
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0.5rem 0', color: '#6b7280', fontSize: '1.25rem' }}>
                                    ↓
                                </div>

                                {}
                                {(() => {
                                    const exitGeo = topExits.find(e => e.ip === pair.exit_ip) || {};
                                    return (
                                        <div>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                                                <Server style={{ width: '0.875rem', height: '0.875rem', color: '#10b981' }} />
                                                <span style={{ fontSize: '0.625rem', color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Exit</span>
                                            </div>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                                <span style={{ fontSize: '1.25rem' }}>{pair.exit_flag || exitGeo.flag || '🌐'}</span>
                                                <p style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'white', margin: 0, fontWeight: '600' }}>
                                                    {pair.exit_ip}
                                                </p>
                                            </div>
                                        </div>
                                    );
                                })()}

                                {}
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginTop: '0.75rem', paddingTop: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                                    <Info style={{ width: '0.875rem', height: '0.875rem', color: '#6b7280' }} />
                                </div>
                            </div>
                        ))}
                    </div>
                ) : topExits.length > 0 ? (
                    
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
                        {topExits.slice(0, 4).map((exit, idx) => (
                            <div
                                key={idx}
                                onClick={() => setSelectedMatch({ guard_ip: topFinding.ip, exit_ip: exit.ip, guard_flag: topFinding.flag, exit_flag: exit.flag, origin_ip: topFinding.origin_ip })}
                                style={{
                                    padding: '1rem',
                                    borderRadius: '0.75rem',
                                    backgroundColor: idx === 0 ? 'rgba(16, 185, 129, 0.1)' : 'rgba(255,255,255,0.03)',
                                    border: idx === 0 ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(255,255,255,0.05)',
                                    cursor: 'pointer'
                                }}
                            >
                                <div style={{ marginBottom: '0.5rem' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                                        <Shield style={{ width: '0.875rem', height: '0.875rem', color: '#3b82f6' }} />
                                        <span style={{ fontSize: '0.625rem', color: '#9ca3af', textTransform: 'uppercase' }}>Guard</span>
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <span style={{ fontSize: '1.25rem' }}>{topFinding.flag || '🌐'}</span>
                                        <p style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'white', margin: 0, fontWeight: '600' }}>
                                            {topFinding.ip || 'Unknown'}
                                        </p>
                                    </div>
                                </div>
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0.5rem 0', color: '#6b7280' }}>↓</div>
                                <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                                        <Server style={{ width: '0.875rem', height: '0.875rem', color: '#10b981' }} />
                                        <span style={{ fontSize: '0.625rem', color: '#9ca3af', textTransform: 'uppercase' }}>Exit</span>
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <span style={{ fontSize: '1.25rem' }}>{exit.flag || '🌐'}</span>
                                        <p style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'white', margin: 0, fontWeight: '600' }}>
                                            {exit.ip}
                                        </p>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '3rem', color: '#9ca3af' }}>
                        <AlertCircle style={{ width: '2.5rem', height: '2.5rem', marginBottom: '0.75rem', opacity: 0.4 }} />
                        <p style={{ fontSize: '0.875rem' }}>No guard-exit matches found</p>
                    </div>
                )}

                {}
                <AnimatePresence>
                    {selectedMatch && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            style={{
                                position: 'fixed',
                                top: 0,
                                left: 0,
                                right: 0,
                                bottom: 0,
                                backgroundColor: 'rgba(0, 0, 0, 0.7)',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                zIndex: 1000
                            }}
                            onClick={() => setSelectedMatch(null)}
                        >
                            <motion.div
                                initial={{ scale: 0.9, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.9, opacity: 0 }}
                                onClick={(e) => e.stopPropagation()}
                                style={{
                                    backgroundColor: '#1a1a2e',
                                    borderRadius: '1rem',
                                    padding: '1.5rem',
                                    width: '400px',
                                    maxWidth: '90vw',
                                    border: '1px solid rgba(16, 185, 129, 0.3)',
                                    boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)'
                                }}
                            >
                                {}
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
                                    <h3 style={{ fontSize: '1rem', fontWeight: 'bold', color: 'white', margin: 0 }}>
                                        🔗 Guard-Exit Match Details
                                    </h3>
                                    <button
                                        onClick={() => setSelectedMatch(null)}
                                        style={{
                                            background: 'none',
                                            border: 'none',
                                            cursor: 'pointer',
                                            padding: '0.25rem',
                                            display: 'flex',
                                            alignItems: 'center',
                                            justifyContent: 'center'
                                        }}
                                    >
                                        <X style={{ width: '1.25rem', height: '1.25rem', color: '#9ca3af' }} />
                                    </button>
                                </div>

                                {}
                                <div style={{
                                    padding: '1rem',
                                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                                    borderRadius: '0.75rem',
                                    border: '1px solid rgba(245, 158, 11, 0.3)',
                                    marginBottom: '0.75rem'
                                }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                                        <User style={{ width: '1rem', height: '1rem', color: '#f59e0b' }} />
                                        <span style={{ fontSize: '0.75rem', color: '#f59e0b', textTransform: 'uppercase', fontWeight: 'bold' }}>Client Origin (Source)</span>
                                    </div>
                                    <p style={{ fontFamily: 'monospace', fontSize: '1.125rem', color: '#f59e0b', margin: 0, fontWeight: '600' }}>
                                        {selectedMatch.origin_ip || topFinding.origin_ip || 'Unknown'}
                                    </p>
                                    <p style={{ fontSize: '0.625rem', color: '#9ca3af', margin: '0.5rem 0 0 0' }}>
                                        This IP connected to the Tor network
                                    </p>
                                </div>

                                {}
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0.5rem 0', color: '#6b7280', fontSize: '1.5rem' }}>
                                    ↓
                                </div>

                                {}
                                <div style={{
                                    padding: '1rem',
                                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                                    borderRadius: '0.75rem',
                                    border: '1px solid rgba(59, 130, 246, 0.3)',
                                    marginBottom: '0.75rem'
                                }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                                        <Shield style={{ width: '1rem', height: '1rem', color: '#3b82f6' }} />
                                        <span style={{ fontSize: '0.75rem', color: '#3b82f6', textTransform: 'uppercase', fontWeight: 'bold' }}>Guard Node</span>
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                        <span style={{ fontSize: '2rem' }}>{selectedMatch.guard_flag || topFinding.flag || '🌐'}</span>
                                        <div>
                                            <p style={{ fontFamily: 'monospace', fontSize: '1.125rem', color: 'white', margin: 0, fontWeight: '600' }}>
                                                {selectedMatch.guard_ip}
                                            </p>
                                            <p style={{ fontSize: '0.75rem', color: '#9ca3af', margin: '0.25rem 0 0 0' }}>
                                                {selectedMatch.guard_country || topFinding.country || 'Unknown Location'}
                                            </p>
                                        </div>
                                    </div>
                                </div>

                                {}
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0.5rem 0', color: '#6b7280', fontSize: '1.5rem' }}>
                                    ↓
                                </div>

                                {}
                                {(() => {
                                    const exitGeo = topExits.find(e => e.ip === selectedMatch.exit_ip) || {};
                                    return (
                                        <div style={{
                                            padding: '1rem',
                                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                                            borderRadius: '0.75rem',
                                            border: '1px solid rgba(16, 185, 129, 0.3)'
                                        }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                                                <Server style={{ width: '1rem', height: '1rem', color: '#10b981' }} />
                                                <span style={{ fontSize: '0.75rem', color: '#10b981', textTransform: 'uppercase', fontWeight: 'bold' }}>Exit Node</span>
                                            </div>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                                <span style={{ fontSize: '2rem' }}>{selectedMatch.exit_flag || exitGeo.flag || '🌐'}</span>
                                                <div>
                                                    <p style={{ fontFamily: 'monospace', fontSize: '1.125rem', color: 'white', margin: 0, fontWeight: '600' }}>
                                                        {selectedMatch.exit_ip}
                                                    </p>
                                                    <p style={{ fontSize: '0.75rem', color: '#9ca3af', margin: '0.25rem 0 0 0' }}>
                                                        {selectedMatch.exit_country || exitGeo.country || 'Unknown Location'}
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    );
                                })()}
                            </motion.div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>

            {}
            <div
                className="panel"
                style={{
                    padding: '1.25rem',
                    background: 'linear-gradient(to right, rgba(16, 185, 129, 0.05), rgba(59, 130, 246, 0.05), transparent)',
                    borderTop: '2px solid rgba(103, 212, 255, 0.3)'
                }}
            >
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <TrendingUp style={{ width: '1.5rem', height: '1.5rem', color: '#67d4ff' }} />
                    <div>
                        <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>
                            <span style={{ color: 'white', fontWeight: '600' }}>✓ Dual-Side Analysis Complete:</span>{' '}
                            {isConfirmed
                                ? `Successfully correlated entry traffic (Guard: ${topFinding.ip}) with exit traffic. ${correlation.session_count || 1} sessions verified.`
                                : `Analyzed guard node with ${topFinding.confidence_level || 'Medium'} confidence. Exit correlation ${matchScore > 0 ? 'partially matched' : 'pending'}.`
                            }
                        </p>
                    </div>
                </div>
            </div>
        </motion.div >
    );
}
