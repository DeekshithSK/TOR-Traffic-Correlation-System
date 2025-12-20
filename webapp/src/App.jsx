import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import axios from 'axios'
import Plot from 'react-plotly.js'
import {
  Upload, FileText, Activity, Shield, AlertTriangle,
  CheckCircle, ArrowRight, ArrowLeftRight, Download, RefreshCw, Server,
  Target, Radio, Eye, Lock, Crosshair, Zap
} from 'lucide-react'

// Components
import Header from './components/Header'
import GlassCard, { CardHeader, CardBody, CardFooter } from './components/GlassCard'
import StatusBadge, { ThreatLevelBadge } from './components/StatusBadge'
import TacticalProgress, { LinearProgress } from './components/TacticalProgress'
import AnalysisTimeline from './components/AnalysisTimeline'
import StepWizard from './components/StepWizard'
import NetworkTopology from './components/NetworkTopology'
import CorrelationModeSwitch from './components/CorrelationModeSwitch'
import RelayGraph from './components/RelayGraph'
import SingleSideDashboard from './components/SingleSideDashboard'
import DualSideDashboard from './components/DualSideDashboard'
import { ANALYSIS_STEPS } from './constants/analysisSteps'
import { ConfidenceMetric } from './components/MetricCard'

// API Configuration
const API_BASE = 'http://localhost:8000/api';

function App() {
  const [view, setView] = useState('upload'); // upload, processing, results
  const [caseInfo, setCaseInfo] = useState(() => ({
    case_id: `CASE-${Math.floor(Date.now() / 1000)}`,
    investigator: ''
  }));
  const [fileData, setFileData] = useState(null);
  const [exitFileData, setExitFileData] = useState(null); // Exit PCAP for guard_exit mode
  const [correlationMode, setCorrelationMode] = useState('guard_only'); // guard_only | guard_exit
  const [analysisResults, setAnalysisResults] = useState(null);
  const [loadingStep, setLoadingStep] = useState(0);
  const [error, setError] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false); // PCAP upload loading state

  // --- File Upload Handler ---
  const handleFileUpload = async (event) => {
    const file = event.target.files?.[0] || event.dataTransfer?.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
      setError(null);
      setIsUploading(true); // Start loading
      const res = await axios.post(`${API_BASE}/upload?case_id=${caseInfo.case_id}`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      setFileData({
        filename: res.data.filename,
        size: res.data.size_kb,
        path: res.data.data_path,
        flow_count: res.data.flow_count
      });
    } catch (err) {
      setError(err.response?.data?.detail || "Evidence upload failed");
    } finally {
      setIsUploading(false); // Stop loading
    }
  };

  // --- Exit File Upload Handler (for guard_exit mode) ---
  const handleExitFileUpload = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
      setError(null);
      const res = await axios.post(`${API_BASE}/upload?case_id=${caseInfo.case_id}&file_type=exit`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      setExitFileData({
        filename: res.data.filename,
        size: res.data.size_kb,
        path: res.data.pcap_path,  // Use full PCAP path for exit correlation
        flow_count: res.data.flow_count
      });
    } catch (err) {
      setError(err.response?.data?.detail || "Exit evidence upload failed");
    }
  };

  // --- Drag and Drop ---
  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => setIsDragging(false);

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    handleFileUpload(e);
  };

  // --- Analysis Handler ---
  const startAnalysis = async () => {
    setView('processing');
    setLoadingStep(0);
    setError(null);

    // Simulated Progress Steps
    for (let i = 0; i < ANALYSIS_STEPS.length; i++) {
      setLoadingStep(i);
      await new Promise(r => setTimeout(r, 1000));
    }

    try {
      // Build analysis request with mode
      console.log('DEBUG: exitFileData =', exitFileData);
      console.log('DEBUG: correlationMode =', correlationMode);

      const params = new URLSearchParams({
        mode: correlationMode,
        ...(exitFileData?.path && { exit_path: exitFileData.path })  // Pass actual PCAP path
      });

      console.log('DEBUG: params =', params.toString());

      const res = await axios.post(`${API_BASE}/analyze/${caseInfo.case_id}?${params}`);
      setAnalysisResults(res.data);
      setView('results');
    } catch (err) {
      // Handle both 'detail' (standard) and 'error' (legacy) response formats
      const errorMsg = err.response?.data?.detail
        || err.response?.data?.error
        || "Analysis pipeline failed. Please check the PCAP file and try again.";
      setError(errorMsg);
      setView('upload');
    }
  };

  // --- Report Download ---
  const downloadReport = async () => {
    try {
      const res = await axios.post(`${API_BASE}/report`, {
        case_info: caseInfo,
        finding_data: analysisResults.top_finding,
        details: analysisResults.details
      }, {
        responseType: 'blob'
      });

      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `Forensic_Report_${caseInfo.case_id}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err);
    }
  };

  // --- Reset ---
  const resetAnalysis = () => {
    setFileData(null);
    setAnalysisResults(null);
    setView('upload');
    setError(null);
    setCaseInfo({ ...caseInfo, case_id: `CASE-${Math.floor(Date.now() / 1000)}` });
  };

  return (
    <div className="relative w-full min-h-screen text-white font-inter overflow-x-hidden">

      {/* Grid Overlay */}
      <div className="fixed inset-0 grid-bg pointer-events-none opacity-50 z-0" />

      {/* Gradient Overlay */}
      <div className="fixed inset-0 bg-gradient-to-b from-ops-black/80 via-transparent to-ops-black/90 pointer-events-none z-0" />

      {/* Header - ensure highest z-index */}
      <Header caseId={caseInfo.case_id} systemStatus="online" />

      {/* Main Container - increased top padding for header clearance */}
      <main className="relative z-10 w-full px-6 pt-20 pb-12">

        <AnimatePresence mode="wait">

          {/* ===================== UPLOAD VIEW ===================== */}
          {view === 'upload' && (
            <motion.div
              key="upload"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0, y: -20 }}
              className="space-y-10 max-w-7xl mx-auto"
            >
              {/* Step Wizard Progress */}
              <StepWizard currentStep="upload" />

              {/* Title Section */}
              <div className="text-center mb-16">
                <motion.div
                  initial={{ opacity: 0, y: -20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="inline-flex items-center gap-3 mb-6"
                >
                  <div className="w-14 h-14 rounded-xl gradient-ops flex items-center justify-center shadow-glow-cyan">
                    <Crosshair className="w-7 h-7 text-white" />
                  </div>
                  <StatusBadge variant="secure" label="SYSTEM READY" showIcon pulse />
                </motion.div>

                <h1 className="font-heading-bold text-4xl md:text-5xl text-white tracking-tight mb-4">
                  SECURE EVIDENCE INTAKE
                </h1>
                <p className="text-text-secondary text-lg max-w-2xl mx-auto leading-relaxed">
                  Upload PCAP evidence for TOR traffic correlation analysis. All evidence is processed in a secure, isolated environment.
                </p>
              </div>

              {/* Main Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-10">

                {/* Left Column: Upload Zone */}
                <div className="lg:col-span-8 space-y-6">

                  {/* Case Info */}
                  <GlassCard variant="glow">
                    <CardHeader title="Investigation Details" icon={FileText} />
                    <CardBody>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="space-y-2">
                          <label className="text-xs font-bold text-text-tertiary uppercase tracking-wider">
                            Case Identifier
                          </label>
                          <input
                            type="text"
                            value={caseInfo.case_id}
                            onChange={(e) => setCaseInfo({ ...caseInfo, case_id: e.target.value })}
                            className="input-tactical w-full"
                          />
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-bold text-text-tertiary uppercase tracking-wider">
                            Lead Investigator
                          </label>
                          <input
                            type="text"
                            value={caseInfo.investigator}
                            onChange={(e) => setCaseInfo({ ...caseInfo, investigator: e.target.value })}
                            placeholder="BADGE # / NAME"
                            className="input-tactical w-full"
                          />
                        </div>
                      </div>
                    </CardBody>
                  </GlassCard>

                  {/* Upload Zone - Conditional layout based on mode */}
                  {correlationMode === 'guard_only' ? (
                    /* Single-Side PCAP: Original single upload zone */
                    <GlassCard
                      variant={isDragging ? 'glow' : 'default'}
                      className="relative overflow-hidden"
                    >
                      <div
                        className={`
                          relative min-h-[400px] border-2 border-dashed rounded-xl m-6 p-10
                          flex flex-col items-center justify-center gap-8 transition-all duration-300
                          ${isDragging
                            ? 'border-ops-cyan bg-ops-cyan/5 scale-[1.02]'
                            : fileData
                              ? 'border-secure/50 bg-secure/5'
                              : 'border-ops-border hover:border-ops-cyan/50'
                          }
                        `}
                        onDragOver={handleDragOver}
                        onDragLeave={handleDragLeave}
                        onDrop={handleDrop}
                      >
                        <input
                          type="file"
                          accept=".pcap,.pcapng"
                          onChange={handleFileUpload}
                          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
                        />

                        {/* Radar Animation */}
                        {!fileData && (
                          <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-20">
                            <div className="w-48 h-48 rounded-full border border-ops-cyan animate-ping" style={{ animationDuration: '3s' }} />
                            <div className="absolute w-32 h-32 rounded-full border border-ops-cyan animate-ping" style={{ animationDuration: '2s' }} />
                          </div>
                        )}

                        {fileData ? (
                          <motion.div
                            initial={{ opacity: 0, scale: 0.9 }}
                            animate={{ opacity: 1, scale: 1 }}
                            className="text-center z-20"
                          >
                            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-secure/20 flex items-center justify-center shadow-glow-green">
                              <CheckCircle className="w-8 h-8 text-secure" />
                            </div>
                            <h4 className="text-xl font-bold text-white mb-2">{fileData.filename}</h4>
                            <div className="flex items-center justify-center gap-4 text-sm text-text-secondary font-mono mb-6">
                              <span>{fileData.size.toFixed(1)} KB</span>
                              <span className="w-1 h-1 rounded-full bg-ops-border" />
                              <span>{fileData.flow_count} FLOWS DETECTED</span>
                            </div>

                            <button
                              onClick={(e) => { e.stopPropagation(); startAnalysis(); }}
                              className="btn-tactical btn-primary"
                            >
                              <Zap className="w-4 h-4" />
                              INITIATE CORRELATION ANALYSIS
                            </button>
                          </motion.div>
                        ) : isUploading ? (
                          <motion.div
                            initial={{ opacity: 0, scale: 0.9 }}
                            animate={{ opacity: 1, scale: 1 }}
                            className="text-center z-20"
                          >
                            <div className="relative w-24 h-24 mx-auto mb-6">
                              <div className="absolute inset-0 rounded-full border-4 border-ops-cyan/20" />
                              <div
                                className="absolute inset-0 rounded-full border-4 border-transparent border-t-ops-cyan animate-spin"
                                style={{ animationDuration: '1s' }}
                              />
                              <div className="absolute inset-3 rounded-full bg-ops-cyan/10 animate-pulse flex items-center justify-center">
                                <Activity className="w-8 h-8 text-ops-cyan" />
                              </div>
                            </div>
                            <h4 className="text-xl font-bold text-white mb-2">Extracting Flows...</h4>
                            <p className="text-text-secondary">Processing PCAP and identifying network flows</p>
                          </motion.div>
                        ) : (
                          <div className="text-center z-20">
                            <div className={`
                              w-20 h-20 mx-auto mb-6 rounded-2xl flex items-center justify-center
                              transition-all duration-300
                              ${isDragging ? 'bg-ops-cyan/20 border-ops-cyan shadow-glow-cyan' : 'bg-ops-panel border-ops-border'} border
                            `}>
                              <Upload className={`w-8 h-8 ${isDragging ? 'text-ops-cyan' : 'text-text-secondary'}`} />
                            </div>
                            <h4 className="text-2xl font-bold text-white mb-2">
                              {isDragging ? 'Release to Upload' : 'Drop PCAP Evidence'}
                            </h4>
                            <p className="text-text-tertiary">or click to browse filesystem</p>
                            <p className="text-xs text-text-muted mt-4 font-mono">SUPPORTED: .pcap, .pcapng</p>
                          </div>
                        )}
                      </div>
                    </GlassCard>
                  ) : (
                    /* Dual-Side PCAP: Two-column upload layout */
                    <GlassCard variant="glow" className="relative overflow-hidden">
                      <CardHeader title="Dual-Side PCAP Evidence" icon={Crosshair} />
                      <CardBody>
                        <div className="grid grid-cols-2 gap-4">
                          {/* Entry/Guard Side PCAP */}
                          <div
                            className={`
                              relative min-h-[280px] border-2 border-dashed rounded-xl p-6
                              flex flex-col items-center justify-center transition-all duration-300
                              ${fileData
                                ? 'border-secure/50 bg-secure/5'
                                : 'border-ops-border hover:border-ops-cyan/50 bg-ops-panel/50'
                              }
                            `}
                          >
                            <input
                              type="file"
                              accept=".pcap,.pcapng"
                              onChange={handleFileUpload}
                              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
                            />
                            <div className="text-center z-20">
                              <div className="text-xs font-bold text-ops-cyan uppercase tracking-wider mb-4">
                                Entry-Side PCAP
                              </div>
                              {fileData ? (
                                <>
                                  <CheckCircle className="w-10 h-10 mx-auto mb-3 text-secure" />
                                  <p className="text-sm font-semibold text-white">{fileData.filename}</p>
                                  <p className="text-xs text-text-tertiary font-mono mt-1">
                                    {fileData.flow_count} flows • {fileData.size.toFixed(1)} KB
                                  </p>
                                </>
                              ) : isUploading ? (
                                <>
                                  <Activity className="w-10 h-10 mx-auto mb-3 text-ops-cyan animate-pulse" />
                                  <p className="text-sm text-text-secondary">Processing...</p>
                                </>
                              ) : (
                                <>
                                  <Upload className="w-10 h-10 mx-auto mb-3 text-text-tertiary" />
                                  <p className="text-sm text-text-secondary">Drop PCAP File</p>
                                  <p className="text-xs text-text-muted mt-1">Client/ISP capture</p>
                                </>
                              )}
                            </div>
                          </div>

                          {/* Exit/Server Side PCAP */}
                          <div
                            className={`
                              relative min-h-[280px] border-2 border-dashed rounded-xl p-6
                              flex flex-col items-center justify-center transition-all duration-300
                              ${exitFileData
                                ? 'border-secure/50 bg-secure/5'
                                : 'border-ops-border hover:border-intel/50 bg-ops-panel/50'
                              }
                            `}
                          >
                            <input
                              type="file"
                              accept=".pcap,.pcapng"
                              onChange={handleExitFileUpload}
                              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
                            />
                            <div className="text-center z-20">
                              <div className="text-xs font-bold text-intel uppercase tracking-wider mb-4">
                                Exit-Side PCAP
                              </div>
                              {exitFileData ? (
                                <>
                                  <CheckCircle className="w-10 h-10 mx-auto mb-3 text-secure" />
                                  <p className="text-sm font-semibold text-white">{exitFileData.filename}</p>
                                  <p className="text-xs text-text-tertiary font-mono mt-1">
                                    {exitFileData.flow_count} flows • {exitFileData.size.toFixed(1)} KB
                                  </p>
                                </>
                              ) : (
                                <>
                                  <Server className="w-10 h-10 mx-auto mb-3 text-text-tertiary" />
                                  <p className="text-sm text-text-secondary">Drop PCAP File</p>
                                  <p className="text-xs text-text-muted mt-1">Victim server capture</p>
                                </>
                              )}
                            </div>
                          </div>
                        </div>

                        {/* Start Analysis Button */}
                        {fileData && (
                          <button
                            onClick={startAnalysis}
                            className="w-full mt-6 btn-tactical btn-primary"
                          >
                            <Zap className="w-4 h-4" />
                            INITIATE DUAL-SIDE CORRELATION
                          </button>
                        )}
                      </CardBody>
                    </GlassCard>
                  )}

                  {/* Error Display */}
                  {error && (
                    <motion.div
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="badge-threat bg-threat/10 border border-threat/30 rounded-xl px-6 py-4 flex items-center gap-4"
                    >
                      <AlertTriangle className="w-5 h-5 text-threat flex-shrink-0" />
                      <span className="text-threat">{error}</span>
                    </motion.div>
                  )}
                </div>

                {/* Right Column: Mode & Protocol */}
                <div className="lg:col-span-4 space-y-6">
                  {/* Correlation Mode Switch */}
                  <GlassCard>
                    <CardBody>
                      <CorrelationModeSwitch
                        mode={correlationMode}
                        onModeChange={setCorrelationMode}
                      />
                    </CardBody>
                  </GlassCard>

                  {/* Protocol Steps */}
                  <GlassCard className="sticky top-24">
                    <CardHeader title="Operational Protocol" icon={Shield} />
                    <CardBody className="space-y-4">
                      {[
                        { num: '01', text: 'Evidence ingested with SHA-256 verification' },
                        { num: '02', text: 'Flows sliced into temporal windows' },
                        { num: '03', text: 'Neural network computes similarity' },
                        {
                          num: '04', text: correlationMode === 'guard_exit'
                            ? 'Dual-Side correlation for enhanced confidence'
                            : 'Single-Side analysis with confidence scoring'
                        }
                      ].map((step, i) => (
                        <div key={i} className="flex gap-3 group">
                          <div className="w-8 h-8 rounded-lg bg-ops-black border border-ops-border flex items-center justify-center font-mono text-ops-cyan font-bold text-xs">
                            {step.num}
                          </div>
                          <p className="text-xs text-text-secondary leading-relaxed flex-1">
                            {step.text}
                          </p>
                        </div>
                      ))}
                    </CardBody>
                    <CardFooter className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className="status-dot status-online animate-pulse" />
                        <span className="text-xs text-text-tertiary font-mono">SYS.READY</span>
                      </div>
                      <span className="text-xs text-text-muted font-mono">v2.0.0</span>
                    </CardFooter>
                  </GlassCard>
                </div>
              </div>
            </motion.div>
          )}

          {/* ===================== PROCESSING VIEW ===================== */}
          {view === 'processing' && (
            <motion.div
              key="processing"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-10 max-w-7xl mx-auto"
            >
              {/* Step Wizard Progress */}
              <StepWizard currentStep="processing" />

              <div className="max-w-2xl w-full mx-auto">
                <GlassCard variant="glow" className="overflow-visible">
                  {/* Classified Banner */}
                  <div className="bg-intel/10 border-b border-intel/30 px-6 py-3 flex items-center justify-center gap-3">
                    <Lock className="w-4 h-4 text-intel" />
                    <span className="text-sm font-bold text-intel uppercase tracking-widest">
                      Classified Analysis in Progress
                    </span>
                  </div>

                  <CardBody className="py-10">
                    <div className="flex flex-col items-center mb-10">
                      <TacticalProgress
                        progress={(loadingStep + 1) / ANALYSIS_STEPS.length * 100}
                        size={160}
                        variant="default"
                        label="CORRELATION"
                      />

                      <motion.p
                        key={loadingStep}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="mt-6 text-text-secondary text-center"
                      >
                        {ANALYSIS_STEPS[loadingStep]?.description}
                      </motion.p>
                    </div>

                    <div className="border-t border-ops-border pt-8">
                      <AnalysisTimeline steps={ANALYSIS_STEPS} currentStep={loadingStep} />
                    </div>
                  </CardBody>

                  <CardFooter className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-text-tertiary text-xs font-mono">
                      <Server className="w-4 h-4" />
                      CASE: {caseInfo.case_id}
                    </div>
                    <div className="flex items-center gap-2">
                      <Activity className="w-4 h-4 text-ops-cyan animate-pulse" />
                      <span className="text-xs text-ops-cyan font-mono">PROCESSING</span>
                    </div>
                  </CardFooter>
                </GlassCard>
              </div>
            </motion.div>
          )}

          {view === 'results' && analysisResults && (
            <motion.div
              key="results"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-6"
            >
              {/* Dashboard Header */}
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-2xl font-bold text-white flex items-center gap-3">
                    <Shield className="w-6 h-6 text-ops-cyan" />
                    TOR TRAFFIC ANALYSIS DASHBOARD
                  </h1>
                  <p className="text-sm text-text-tertiary mt-1">
                    Tracing Tor network users by correlating traffic patterns to identify probable origin IPs
                  </p>
                </div>
                <div className="flex items-center gap-4">
                  <span className="text-xs font-mono text-text-tertiary">CASE: {caseInfo.case_id}</span>
                  <button onClick={resetAnalysis} className="btn-tactical btn-ghost text-xs">
                    <RefreshCw className="w-3 h-3" /> NEW
                  </button>
                </div>
              </div>

              {/* Conditional Dashboard Rendering Based on Analysis Mode */}
              <div style={{ padding: '2rem 1.5rem', marginTop: '1rem' }}>
                {analysisResults.analysis_mode === 'exit_only' || analysisResults.analysis_mode === 'entry_only' ? (
                  /* Single-Side PCAP Analysis Dashboard */
                  <SingleSideDashboard results={analysisResults} />
                ) : (
                  /* Dual-Side PCAP Analysis Dashboard */
                  <DualSideDashboard results={analysisResults} />
                )}
              </div>

              {/* Legacy Grid - Hidden when using new dashboards */}
              {false && (
                <div
                  className="gap-8 py-6"
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(12, 1fr)',
                    gap: '2rem',
                    alignItems: 'start',
                    paddingTop: '1.5rem',
                    paddingBottom: '1.5rem'
                  }}
                >

                  {/* FIRST ROW: Key Findings - Guard, Exit, Entry-Exit Matching */}
                  <div style={{ gridColumn: 'span 12', display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>

                    {/* Inferred Guard Node (or Mode-Specific View) */}
                    <div className="panel p-5">
                      <div className="flex items-center gap-2 mb-3">
                        <Target className="w-4 h-4 text-ops-cyan" />
                        <h4 className="text-xs font-bold text-text-tertiary uppercase tracking-wider">
                          {analysisResults.analysis_mode === 'exit_only'
                            ? '🔍 Exit-Side Analysis'
                            : analysisResults.analysis_mode === 'entry_only'
                              ? '🔍 Entry-Side Analysis'
                              : 'Inferred Guard Node'}
                        </h4>
                        {analysisResults.analysis_mode && (
                          <span className="text-[9px] px-2 py-0.5 bg-intel/20 text-intel rounded-full">
                            AUTO-DETECTED
                          </span>
                        )}
                      </div>
                      {analysisResults.analysis_mode === 'exit_only' ? (
                        /* Exit-Only Mode: Show probable guard if detected */
                        <div className="space-y-3">
                          {analysisResults.correlation?.probable_guards?.length > 0 ? (
                            /* Probable guard detected */
                            <>
                              <div className="flex items-center gap-2 mb-2">
                                <span className="text-xl">{analysisResults.correlation.probable_guards[0].flag || '🌐'}</span>
                                <div>
                                  <p className="font-mono text-sm text-secure">{analysisResults.correlation.probable_guards[0].ip}</p>
                                  <p className="text-[10px] text-text-muted">{analysisResults.correlation.probable_guards[0].country}</p>
                                </div>
                                {analysisResults.correlation.probable_guards[0].in_consensus && (
                                  <span className="px-2 py-0.5 bg-secure/20 text-secure text-[9px] rounded-full">📡 TOR CONSENSUS</span>
                                )}
                              </div>
                              <div className="text-[10px] text-text-tertiary space-y-1">
                                <p>ISP: <span className="text-text-secondary">{analysisResults.correlation.probable_guards[0].isp}</span></p>
                                <p>Confidence: <span className="text-secure font-bold">{(analysisResults.correlation.probable_guards[0].guard_probability * 100).toFixed(0)}%</span></p>
                                {analysisResults.correlation.probable_guards[0].relay_bandwidth > 0 && (
                                  <p>Bandwidth: <span className="text-intel">{(analysisResults.correlation.probable_guards[0].relay_bandwidth / 1000000).toFixed(1)} MB/s</span></p>
                                )}
                                <p className="text-amber-400 mt-1 text-[9px]">🔍 {analysisResults.correlation.probable_guards[0].reason}</p>
                              </div>
                            </>
                          ) : (
                            /* No guard detected */
                            <>
                              <div className="flex items-center gap-2 mb-2">
                                <span className="text-xl">📊</span>
                                <div>
                                  <p className="font-mono text-sm text-intel">Exit-Side Analysis</p>
                                  <p className="text-[10px] text-text-muted">No entry PCAP available</p>
                                </div>
                              </div>
                              <div className="text-[10px] text-text-tertiary space-y-1">
                                <p>Mode: <span className="text-intel font-semibold">Exit-Only</span></p>
                                <p>Flows: <span className="text-text-secondary">{analysisResults.flow_metadata?.total_flows || 0}</span></p>
                                <p>CDN Filtered: <span className="text-text-secondary">{analysisResults.flow_metadata?.cdn_filtered || 0}</span></p>
                              </div>
                            </>
                          )}
                        </div>
                      ) : (
                        /* Normal Mode: Show Guard Node */
                        <>
                          <div className="flex items-center gap-2 mb-2">
                            <span className="text-xl">{analysisResults.top_finding.flag || '🌐'}</span>
                            <div>
                              <p className="font-mono text-sm text-white">
                                {analysisResults.top_finding.ip ||
                                  (() => {
                                    const parts = (analysisResults.top_finding.guard_node || '').split('_');
                                    return parts.length >= 3 ? parts[2] : analysisResults.top_finding.guard_node;
                                  })()}
                              </p>
                              <p className="text-[10px] text-text-muted">{analysisResults.top_finding.country || 'Unknown'}</p>
                            </div>
                          </div>
                          <div className="text-[10px] text-text-tertiary space-y-1">
                            <p>ASN: <span className="text-text-secondary">{analysisResults.top_finding.isp || 'Unknown'}</span></p>
                            <p>Role: <span className="text-secure font-semibold">Guard Relay</span></p>
                          </div>
                        </>
                      )}
                    </div>

                    {/* Inferred Exit Nodes (Top 3) */}
                    <div className="panel p-5">
                      <div className="flex items-center gap-2 mb-3">
                        <Server className="w-4 h-4 text-intel" />
                        <h4 className="text-xs font-bold text-text-tertiary uppercase tracking-wider">Top Exit Nodes</h4>
                      </div>
                      {analysisResults.correlation?.top_exit_nodes?.length > 0 ? (
                        <div className="space-y-3">
                          {analysisResults.correlation.top_exit_nodes.map((exit, idx) => (
                            <div key={idx} className={`flex items-center gap-3 p-2 rounded ${idx === 0 ? 'bg-secure/10 border border-secure/30' : 'bg-surface-elevated/50'}`}>
                              <span className="text-lg">{exit.flag || '🌐'}</span>
                              <div className="flex-1 min-w-0">
                                <p className="font-mono text-xs text-white truncate">{exit.ip}</p>
                                <p className="text-[10px] text-text-muted truncate">{exit.country} • {exit.isp?.slice(0, 20)}</p>
                              </div>
                              <div className="text-right">
                                <span className={`text-xs font-bold ${idx === 0 ? 'text-secure' : 'text-text-secondary'}`}>
                                  {(exit.score * 100).toFixed(0)}%
                                </span>
                                {idx === 0 && <span className="block text-[9px] text-secure">TOP MATCH</span>}
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : analysisResults.correlation?.observed_exit_flow ? (
                        <>
                          <div className="flex items-center gap-2 mb-2">
                            <span className="text-xl">{analysisResults.correlation?.exit_geo?.flag || '🌐'}</span>
                            <div>
                              <p className="font-mono text-sm text-white">
                                {analysisResults.correlation?.exit_geo?.ip || 'Unknown'}
                              </p>
                              <p className="text-[10px] text-text-muted">
                                {analysisResults.correlation?.exit_geo?.country || 'Exit Relay'}
                              </p>
                            </div>
                          </div>
                          <div className="text-[10px] text-text-tertiary space-y-1">
                            <p>ASN: <span className="text-text-secondary">{analysisResults.correlation?.exit_geo?.isp || 'Unknown'}</span></p>
                          </div>
                        </>
                      ) : (
                        <div className="flex items-center justify-center h-16 text-text-muted text-xs">
                          No exit data available
                        </div>
                      )}
                    </div>

                    {/* Entry-Exit Matching Score */}
                    <div className="panel p-5 border-l-2 border-ops-cyan">
                      <div className="flex items-center gap-2 mb-3">
                        <CheckCircle className="w-4 h-4 text-ops-cyan" />
                        <h4 className="text-xs font-bold text-text-tertiary uppercase tracking-wider">Entry-Exit Matching</h4>
                      </div>
                      <div className="flex items-center justify-between mb-2">
                        <span className={`font-mono text-2xl font-bold ${(analysisResults.correlation?.exit_boosted_score || analysisResults.correlation?.exit_direct_score || 0) >= 0.5 ? 'text-secure'
                          : (analysisResults.correlation?.exit_boosted_score || analysisResults.correlation?.exit_direct_score || 0) >= 0.25 ? 'text-intel'
                            : 'text-threat'
                          }`}>
                          {(analysisResults.correlation?.exit_boosted_score || analysisResults.correlation?.exit_direct_score)
                            ? `${((analysisResults.correlation?.exit_boosted_score || analysisResults.correlation?.exit_direct_score) * 100).toFixed(1)}%`
                            : 'N/A'}
                        </span>
                        <span className={`text-[10px] font-semibold px-2 py-1 rounded ${analysisResults.correlation?.exit_confirmation
                          ? 'bg-secure/10 text-secure'
                          : (analysisResults.correlation?.exit_boosted_score || analysisResults.correlation?.exit_direct_score || 0) > 0
                            ? 'bg-intel/10 text-intel'
                            : 'bg-ops-panel text-text-muted'
                          }`}>
                          {analysisResults.correlation?.exit_confirmation
                            ? 'Confirmed'
                            : (analysisResults.correlation?.exit_boosted_score || analysisResults.correlation?.exit_direct_score || 0) > 0
                              ? 'Indirect'
                              : 'No Data'}
                        </span>
                      </div>
                      <p className="text-[10px] text-text-muted">
                        {analysisResults.correlation?.exit_confirmation
                          ? 'Direct pattern match above 50% threshold'
                          : (analysisResults.correlation?.exit_boosted_score || analysisResults.correlation?.exit_direct_score || 0) > 0
                            ? `${analysisResults.correlation?.session_count || 1} sessions corroborated`
                            : 'No exit-side PCAP provided'}
                      </p>
                    </div>
                  </div>

                  {/* LEFT COLUMN: Confidence + Evidence Details */}
                  <div style={{ gridColumn: 'span 4', display: 'flex', flexDirection: 'column', gap: '2rem' }}>

                    {/* Confidence Indicator Card */}
                    <div className="panel p-6">
                      <div className="flex items-start gap-4">
                        <div className={`
                        w-12 h-12 rounded-full flex items-center justify-center
                        ${analysisResults.top_finding.confidence_level === 'High'
                            ? 'bg-secure/20 border-2 border-secure'
                            : 'bg-intel/20 border-2 border-intel'
                          }
                      `}>
                          <CheckCircle className={`w-6 h-6 ${analysisResults.top_finding.confidence_level === 'High' ? 'text-secure' : 'text-intel'
                            }`} />
                        </div>
                        <div className="flex-1">
                          <h3 className="text-lg font-bold text-white">
                            {analysisResults.top_finding.confidence_level} Confidence
                            <span className="text-ops-cyan ml-2">
                              ({(analysisResults.top_finding.confidence_score * 100).toFixed(0)}%)
                            </span>
                          </h3>
                          <p className="text-xs text-text-secondary mt-1">
                            Confidence is statistically supported and reflects {
                              analysisResults.correlation?.exit_confirmation
                                ? 'both guard and exit correlation (confirmed)'
                                : analysisResults.correlation?.mode === 'guard+exit_indirect'
                                  ? 'guard correlation with indirect exit evidence'
                                  : 'guard correlation analysis'
                            }.
                          </p>
                        </div>
                      </div>
                      <div className="mt-4 pt-3 border-t border-ops-border">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-bold text-text-tertiary uppercase">CORRELATION MODE:</span>
                          <span className={`text-xs font-semibold ${analysisResults.correlation?.mode?.includes('guard+exit') ? 'text-secure' : 'text-intel'
                            }`}>
                            {analysisResults.correlation?.mode === 'guard+exit_confirmed'
                              ? 'Dual-Side PCAP (Confirmed)'
                              : analysisResults.correlation?.mode === 'guard+exit_indirect'
                                ? 'Dual-Side PCAP (Indirect)'
                                : 'Single-Side PCAP Analysis'}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Indirect Exit Evidence (if present but below confirmation threshold) */}
                    {analysisResults.correlation?.mode === 'guard+exit_indirect' && (
                      <div className="panel p-6 border-l-2 border-intel">
                        <div className="flex items-center gap-2 mb-4">
                          <Server className="w-4 h-4 text-intel" />
                          <h4 className="text-xs font-bold text-text-tertiary uppercase tracking-wider">Indirect Exit Evidence</h4>
                          <span className="ml-auto text-[10px] font-mono text-intel bg-intel/10 px-2 py-0.5 rounded">
                            +{((analysisResults.correlation?.exit_boost || 0) * 100).toFixed(1)}% boost
                          </span>
                        </div>

                        {/* Matched Flow Pair */}
                        {analysisResults.correlation?.observed_exit_flow && (
                          <div className="mb-4">
                            <p className="text-[9px] text-text-tertiary uppercase mb-2">Matched Flow Pair</p>
                            <div className="space-y-2 bg-ops-panel/50 rounded p-3">
                              {/* Entry (Guard) Flow */}
                              {analysisResults.correlation?.matched_guard_flow && (
                                <div className="flex items-center justify-between text-[11px] pb-2 border-b border-ops-border/50">
                                  <span className="text-text-tertiary">Entry Flow:</span>
                                  <span className="font-mono text-ops-cyan text-[10px] truncate max-w-[200px]" title={analysisResults.correlation.matched_guard_flow}>
                                    {analysisResults.correlation.matched_guard_flow}
                                  </span>
                                </div>
                              )}
                              {/* Exit Flow */}
                              <div className="flex items-center justify-between text-[11px]">
                                <span className="text-text-tertiary">Exit Flow:</span>
                                <span className="font-mono text-white text-[10px] truncate max-w-[200px]" title={analysisResults.correlation.observed_exit_flow}>
                                  {analysisResults.correlation.observed_exit_flow}
                                </span>
                              </div>
                            </div>
                            <div className="flex items-center justify-between mt-2 text-[10px]">
                              <div className="flex items-center gap-2">
                                <span className="text-text-tertiary">Pattern match:</span>
                                <span className="text-intel font-mono">
                                  {((analysisResults.correlation?.exit_direct_score || 0) * 100).toFixed(1)}%
                                </span>
                              </div>
                              {analysisResults.correlation?.guard_flows_count > 0 && (
                                <span className="text-text-muted">
                                  ({analysisResults.correlation.guard_flows_count} guard flows analyzed)
                                </span>
                              )}
                            </div>
                          </div>
                        )}

                        <p className="text-[10px] text-text-muted mb-3">
                          Exit data present but direct correlation below threshold.
                          Partial confidence boost applied from circumstantial indicators.
                        </p>

                        {/* Factor breakdown */}
                        {analysisResults.correlation?.indirect_evidence?.factor_scores && (
                          <div className="space-y-1.5 border-t border-ops-border pt-3">
                            {Object.entries(analysisResults.correlation.indirect_evidence.factor_scores).map(([factor, score]) => (
                              <div key={factor} className="flex items-center justify-between text-[10px]">
                                <span className="text-text-muted">{factor.replace(/_/g, ' ')}</span>
                                <span className="font-mono text-intel">+{(score * 100).toFixed(1)}%</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Guard-Exit Matches Panel (Entry-Exit Correlation) */}
                    {analysisResults.correlation?.guard_exit_pairs && analysisResults.correlation.guard_exit_pairs.length > 0 && (
                      <details className="panel group" open>
                        <summary className="p-4 cursor-pointer flex items-center justify-between hover:bg-ops-panel/50 transition-colors">
                          <div className="flex items-center gap-2">
                            <ArrowLeftRight className="w-4 h-4 text-secure" />
                            <h4 className="text-xs font-bold text-text-tertiary uppercase tracking-wider">Guard-Exit Matches ({analysisResults.correlation.guard_exit_pairs.length})</h4>
                          </div>
                          <span className="text-text-muted text-xs group-open:hidden">Click to expand</span>
                          <span className="text-text-muted text-xs hidden group-open:inline">Click to collapse</span>
                        </summary>
                        <div className="p-4 pt-0 border-t border-ops-border/50">
                          {/* Header */}
                          <div className="bg-secure/10 border border-secure/30 rounded-lg px-3 py-2 mb-4">
                            <p className="text-[10px] text-secure leading-relaxed">
                              🔗 <b>GUARD-EXIT CORRELATION</b> — Entry PCAP guard nodes matched against exit PCAP traffic patterns.
                              Higher combined score = stronger entry-exit link.
                            </p>
                          </div>

                          {/* Pairs Table */}
                          <div className="space-y-2">
                            {analysisResults.correlation.guard_exit_pairs.slice(0, 10).map((pair, idx) => (
                              <div
                                key={`${pair.guard_ip}-${pair.exit_ip}-${idx}`}
                                className={`flex items-center justify-between p-3 rounded-lg border transition-all ${pair.matched
                                  ? 'bg-secure/10 border-secure/40'
                                  : 'bg-ops-panel/30 border-ops-border/30 hover:border-ops-border/50'
                                  }`}
                              >
                                <div className="flex items-center gap-3">
                                  {/* Rank Badge */}
                                  <span className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold ${pair.matched ? 'bg-secure text-white' : 'bg-ops-panel text-text-muted'
                                    }`}>
                                    {idx + 1}
                                  </span>

                                  {/* Guard → Exit */}
                                  <div className="flex items-center gap-2">
                                    <div>
                                      <span className="font-mono text-xs text-white">{pair.guard_ip && pair.guard_ip.length > 18 ? pair.guard_ip.slice(0, 18) + '...' : pair.guard_ip}</span>
                                      <div className="text-[9px] text-text-muted">Guard ({(pair.guard_confidence * 100).toFixed(0)}%)</div>
                                    </div>
                                    <span className="text-text-muted">→</span>
                                    <div>
                                      <span className="font-mono text-xs text-white">{pair.exit_ip && pair.exit_ip.length > 18 ? pair.exit_ip.slice(0, 18) + '...' : pair.exit_ip}</span>
                                      <div className="text-[9px] text-text-muted">Exit ({(pair.exit_score * 100).toFixed(0)}%)</div>
                                    </div>
                                  </div>
                                </div>

                                {/* Match Status & Combined Score */}
                                <div className="flex items-center gap-3">
                                  <span className={`text-[10px] ${pair.matched ? 'text-secure' : 'text-text-muted'}`}>
                                    {pair.matched ? '✓ MATCHED' : '○ NO MATCH'}
                                  </span>
                                  <div className={`px-3 py-1 rounded text-xs font-bold ${pair.combined_score >= 0.6
                                    ? 'bg-secure/20 text-secure'
                                    : pair.combined_score >= 0.4
                                      ? 'bg-intel/20 text-intel'
                                      : 'bg-ops-panel text-text-muted'
                                    }`}>
                                    {(pair.combined_score * 100).toFixed(1)}%
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </details>
                    )}

                    {/* IP Leads Panel (Forensic Intelligence) */}
                    {analysisResults.ip_leads && analysisResults.ip_leads.length > 0 && (
                      <details className="panel group" open>
                        <summary className="p-4 cursor-pointer flex items-center justify-between hover:bg-ops-panel/50 transition-colors">
                          <div className="flex items-center gap-2">
                            <Target className="w-4 h-4 text-threat" />
                            <h4 className="text-xs font-bold text-text-tertiary uppercase tracking-wider">IP Leads ({analysisResults.ip_leads.length})</h4>
                          </div>
                          <span className="text-text-muted text-xs group-open:hidden">Click to expand</span>
                          <span className="text-text-muted text-xs hidden group-open:inline">Click to collapse</span>
                        </summary>
                        <div className="p-4 pt-0 border-t border-ops-border/50">
                          {/* IP Leads Header */}
                          <div className="bg-threat/10 border border-threat/30 rounded-lg px-3 py-2 mb-4">
                            <p className="text-[10px] text-threat leading-relaxed">
                              🎯 <b>ACTIONABLE IP LEADS</b> — Aggregated from correlated traffic flows.
                              Higher confidence = stronger forensic evidence.
                            </p>
                          </div>

                          {/* IP Leads Table */}
                          <div className="space-y-2">
                            {analysisResults.ip_leads.slice(0, 10).map((lead, idx) => (
                              <div
                                key={lead.ip}
                                className={`flex items-center justify-between p-3 rounded-lg border transition-all ${idx === 0
                                  ? 'bg-threat/10 border-threat/40'
                                  : 'bg-ops-panel/30 border-ops-border/30 hover:border-ops-border/50'
                                  }`}
                              >
                                <div className="flex items-center gap-3">
                                  {/* Rank Badge */}
                                  <span className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold ${idx === 0 ? 'bg-threat text-white' : 'bg-ops-panel text-text-muted'
                                    }`}>
                                    {idx + 1}
                                  </span>

                                  {/* IP Address */}
                                  <div>
                                    <span className="font-mono text-sm text-white">{lead.ip}</span>
                                    <div className="text-[10px] text-text-muted">
                                      {lead.flow_count} correlated flow{lead.flow_count !== 1 ? 's' : ''}
                                    </div>
                                  </div>
                                </div>

                                {/* Confidence & Evidence */}
                                <div className="flex items-center gap-4">
                                  {/* Evidence Breakdown */}
                                  <div className="text-right text-[10px]">
                                    <div className="text-text-tertiary">
                                      Stat: <span className="text-intel">{(lead.evidence?.avg_statistical * 100).toFixed(1)}%</span>
                                    </div>
                                    {lead.evidence?.avg_siamese && (
                                      <div className="text-text-tertiary">
                                        Siamese: <span className="text-intel">{(lead.evidence.avg_siamese * 100).toFixed(1)}%</span>
                                      </div>
                                    )}
                                    {/* Exit Score - shown when in dual-side mode */}
                                    {lead.exit_score !== undefined && lead.exit_score > 0 && (
                                      <div className="text-text-tertiary">
                                        Exit: <span className={lead.exit_matched ? 'text-secure font-semibold' : 'text-intel'}>{(lead.exit_score * 100).toFixed(1)}%</span>
                                      </div>
                                    )}
                                  </div>

                                  {/* Confidence Badge - use combined_score in dual-side mode */}
                                  <div className={`px-3 py-1 rounded text-xs font-bold ${(lead.combined_score || lead.confidence) >= 0.75
                                    ? 'bg-threat/20 text-threat'
                                    : (lead.combined_score || lead.confidence) >= 0.5
                                      ? 'bg-intel/20 text-intel'
                                      : 'bg-ops-panel text-text-muted'
                                    }`}>
                                    {((lead.combined_score || lead.confidence) * 100).toFixed(1)}%
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>

                          {/* More indicator */}
                          {analysisResults.ip_leads.length > 10 && (
                            <p className="text-[10px] text-text-muted mt-3 text-center">
                              + {analysisResults.ip_leads.length - 10} more IP leads in full report
                            </p>
                          )}
                        </div>
                      </details>
                    )}

                    {/* Export Button */}
                    <button
                      onClick={downloadReport}
                      className="w-full btn-tactical btn-primary flex items-center justify-center gap-3"
                    >
                      <Download className="w-5 h-5" />
                      <span className="text-sm font-bold uppercase tracking-wider">Export Report</span>
                    </button>
                  </div>

                  {/* CENTER COLUMN: Case Details + Chart + Detailed Info */}
                  <div style={{ gridColumn: 'span 5', display: 'flex', flexDirection: 'column', gap: '1rem' }}>

                    {/* Case Details */}
                    <div className="panel p-6">
                      <div className="flex items-center justify-between mb-4">
                        <h4 className="text-sm font-bold text-white uppercase tracking-wider">Case Details</h4>
                        <div className={`
                        px-3 py-1 rounded-full text-[10px] font-semibold flex items-center gap-1
                        ${analysisResults.correlation?.exit_confirmation
                            ? 'bg-secure/20 text-secure border border-secure/30'
                            : 'bg-intel/20 text-intel border border-intel/30'
                          }
                      `}>
                          <div className="w-1.5 h-1.5 rounded-full bg-current" />
                          {analysisResults.correlation?.mode === 'guard+exit_confirmed'
                            ? 'Dual-Side (Confirmed)'
                            : analysisResults.correlation?.mode === 'guard+exit_indirect'
                              ? 'Dual-Side (Indirect)'
                              : 'Single-Side PCAP'}
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div className="flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-ops-cyan" />
                          <span className="text-text-tertiary">Duration:</span>
                          <span className="text-white font-mono">~5m 30s</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-ops-cyan" />
                          <span className="text-text-tertiary">Packets:</span>
                          <span className="text-white font-mono">{fileData?.flow_count || 'N/A'}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-ops-cyan" />
                          <span className="text-text-tertiary">Exit Data:</span>
                          <span className={`${analysisResults.correlation?.exit_confirmation ? 'text-secure' : analysisResults.correlation?.mode === 'guard+exit_indirect' ? 'text-intel' : 'text-white'}`}>
                            {analysisResults.correlation?.exit_confirmation
                              ? 'Confirmed'
                              : analysisResults.correlation?.mode === 'guard+exit_indirect'
                                ? 'Indirect Evidence'
                                : 'Not Available'}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-ops-cyan" />
                          <span className="text-text-tertiary">Offset:</span>
                          <span className="text-white font-mono">±5ms</span>
                        </div>
                      </div>
                    </div>

                    {/* Entry-Exit Matching Progression Chart - only show if 2+ sessions AND exit data */}
                    {analysisResults.correlation?.per_session_scores?.length >= 2 && (
                      <div className="panel p-6">
                        <h4 className="text-sm font-bold text-white uppercase tracking-wider mb-4">Entry-Exit Matching Progression</h4>
                        <div className="h-[200px]">
                          <Plot
                            data={[
                              {
                                // Show cumulative confidence: boost for matches, penalty for non-matches
                                x: analysisResults.correlation.per_session_scores.map((_, i) => i),
                                y: (() => {
                                  const sessions = analysisResults.correlation.per_session_scores;
                                  let cumulative = 0;
                                  return sessions.map((session, i) => {
                                    // Start with session score, apply cumulative adjustment
                                    // Match (>50%): boost confidence
                                    // Non-match (<50%): slight penalty
                                    if (session.matched) {
                                      cumulative += 0.1 * (1 + 0.1 * Math.log(i + 1)); // Diminishing boost
                                    } else {
                                      cumulative -= 0.05; // Penalty for non-match
                                    }
                                    // Base is session score, adjusted by cumulative boost/penalty
                                    const adjusted = Math.max(0, Math.min(session.score + cumulative, 0.999));
                                    return adjusted * 100;
                                  });
                                })(),
                                type: 'scatter',
                                mode: 'lines+markers',
                                line: {
                                  shape: 'spline',
                                  width: 2,
                                  color: '#67d4ff'
                                },
                                marker: {
                                  size: 8,
                                  // Color based on match status
                                  color: analysisResults.correlation.per_session_scores.map(s =>
                                    s.matched ? '#10b981' : '#ef4444'
                                  )
                                },
                                fill: 'tozeroy',
                                fillcolor: 'rgba(103, 212, 255, 0.1)'
                              }
                            ]}
                            layout={{
                              paper_bgcolor: 'transparent',
                              plot_bgcolor: 'transparent',
                              margin: { l: 40, r: 20, t: 10, b: 40 },
                              xaxis: {
                                title: { text: '', font: { size: 10, color: '#6b7280' } },
                                showgrid: false,
                                zeroline: false,
                                tickfont: { size: 10, color: '#6b7280' },
                                tickvals: analysisResults.correlation.per_session_scores.map((_, i) => i),
                                ticktext: analysisResults.correlation.per_session_scores.map((_, i) => `Session ${i + 1}`)
                              },
                              yaxis: {
                                title: { text: '', font: { size: 10, color: '#6b7280' } },
                                showgrid: true,
                                gridcolor: '#21262d',
                                zeroline: false,
                                tickfont: { size: 10, color: '#6b7280' },
                                ticksuffix: '%',
                                range: [0, Math.max(60, (analysisResults.correlation?.exit_boosted_score || analysisResults.correlation?.exit_direct_score || 0.5) * 100 + 15)]
                              },
                              showlegend: false,
                              autosize: true
                            }}
                            useResizeHandler={true}
                            style={{ width: "100%", height: "100%" }}
                            config={{ displayModeBar: false }}
                          />
                        </div>
                      </div>
                    )}

                    {/* Detailed Info */}
                    <div className="panel p-6">
                      <h4 className="text-sm font-bold text-white uppercase tracking-wider mb-4">Detailed Info</h4>
                      <div className="grid grid-cols-2 gap-4 text-sm mb-4">
                        <div className="flex items-center gap-2">
                          <Activity className="w-4 h-4 text-text-tertiary" />
                          <span className="text-text-tertiary">Flow Windows:</span>
                          <span className="text-white font-semibold">{analysisResults.top_finding.correlated_sessions}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Lock className="w-4 h-4 text-text-tertiary" />
                          <span className="text-text-tertiary">Packets Analyzed:</span>
                          <span className="text-white font-semibold">{fileData?.flow_count || 'N/A'}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <CheckCircle className="w-4 h-4 text-secure" />
                          <span className="text-text-tertiary">Timing Consistency:</span>
                          <span className="text-secure font-semibold">High</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <CheckCircle className="w-4 h-4 text-secure" />
                          <span className="text-text-tertiary">Burst Similarity:</span>
                          <span className="text-secure font-semibold">Strong</span>
                        </div>
                      </div>
                      <p className="text-xs text-text-tertiary pt-3 border-t border-ops-border">
                        Exit-side correlation strengthens confidence when exit data is available. Middle hops remain unobservable by design.
                      </p>
                    </div>
                  </div>

                  {/* RIGHT COLUMN: Globe + Export */}
                  <div style={{ gridColumn: 'span 3', display: 'flex', flexDirection: 'column', gap: '1rem' }}>

                    {/* Globe Visualization */}
                    <div className="panel p-6 min-h-[200px] flex flex-col items-center justify-center relative overflow-hidden">
                      <div className="absolute inset-0 opacity-30">
                        <div className="absolute inset-0 bg-gradient-radial from-ops-cyan/20 to-transparent" />
                      </div>
                      <div className="relative z-10 text-center">
                        <div className="w-20 h-20 mx-auto mb-4 rounded-full border-2 border-ops-cyan/30 flex items-center justify-center">
                          <span className="text-4xl">{analysisResults.top_finding.flag || '🌐'}</span>
                        </div>
                        <p className="text-xl font-bold text-white mb-1">{analysisResults.top_finding.country}</p>
                        <p className="text-sm text-text-tertiary mb-4">{analysisResults.top_finding.city}</p>
                        <span className="text-[9px] text-text-muted font-mono uppercase tracking-widest">TOR CIRCUIT</span>
                      </div>
                    </div>

                    {/* Export Report Button */}
                    <button
                      onClick={downloadReport}
                      className="w-full btn-tactical btn-primary flex items-center justify-center gap-3"
                    >
                      <Download className="w-5 h-5" />
                      <span className="text-sm font-bold uppercase tracking-wider">Export Report</span>
                    </button>
                  </div>
                </div>
              )}

            </motion.div>
          )}

        </AnimatePresence>

        {/* Footer */}
        <footer className="mt-16 text-center">
          <p className="text-text-muted text-xs uppercase tracking-[0.3em]">
            ⚠ Restricted Access • Law Enforcement Only • Evidence Handling Protocol
          </p>
        </footer>
      </main>
    </div >
  )
}

export default App
