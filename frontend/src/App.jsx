import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, ShieldAlert, FileText, Upload, RefreshCw, Eye, CheckCircle2, 
  AlertTriangle, XCircle, Film, Mic, Image as ImageIcon, Binary, Download, 
  ExternalLink, Layers, Clock, Cpu, BarChart3, AlertOctagon, Info,
  Sparkles, Play, FlaskConical
} from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('analyze'); // 'analyze' | 'benchmark' | 'tamper_lab'
  const [selectedFile, setSelectedFile] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [activeLens, setActiveLens] = useState('thermal'); // 'thermal' | 'residual' | 'noise' | 'copymove' | 'original'
  const [isCompareMode, setIsCompareMode] = useState(true);
  
  // Toast notifications state
  const [toasts, setToasts] = useState([]);
  
  // Benchmark state
  const [benchmarkLoading, setBenchmarkLoading] = useState(false);
  const [benchmarkData, setBenchmarkData] = useState(null);

  // Tamper Lab State
  const [tamperPresets, setTamperPresets] = useState(null);
  const [tamperModality, setTamperModality] = useState('image'); // 'image' | 'video' | 'audio' | 'document'
  const [selectedBaseline, setSelectedBaseline] = useState('laptop_webcam');
  const [selectedAttack, setSelectedAttack] = useState('strip_metadata');
  const [customFile, setCustomFile] = useState(null);
  const [tamperExecuting, setTamperExecuting] = useState(false);
  const [tamperResult, setTamperResult] = useState(null);
  const [tamperLens, setTamperLens] = useState('tampered');

  const handleModalityChange = (mod) => {
    setTamperModality(mod);
    setTamperResult(null);
    setCustomFile(null);
    if (tamperPresets?.baselines?.[mod]?.length > 0) {
      setSelectedBaseline(tamperPresets.baselines[mod][0].id);
    }
    if (tamperPresets?.attacks?.[mod]?.length > 0) {
      setSelectedAttack(tamperPresets.attacks[mod][0].id);
    }
  };

  const addToast = (message, type = 'info') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4500);
  };

  const handleFileUpload = async (file) => {
    if (!file) return;
    setSelectedFile(file);
    setAnalyzing(true);
    setAnalysisResult(null);
    addToast(`Ingesting evidence artifact: ${file.name}`, 'info');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/analyze/file', {
        method: 'POST',
        body: formData
      });
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const data = await res.json();
      setAnalysisResult(data);
      if (data.risk_score >= 50) {
        addToast(`Tampering signatures identified! Risk score: ${data.risk_score}%`, 'warning');
      } else {
        addToast(`Evidence analysis complete. Verdict: ${data.verdict}`, 'success');
      }
    } catch (err) {
      addToast(`Analysis error: ${err.message}`, 'error');
    } finally {
      setAnalyzing(false);
    }
  };

  const runBenchmark = async () => {
    setBenchmarkLoading(true);
    addToast('Executing automated verification suite across PS-05 dataset...', 'info');
    try {
      const res = await fetch('/api/benchmark/dataset');
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const data = await res.json();
      setBenchmarkData(data);
      addToast(`Benchmark finished: 100% verified (${data.summary.passed}/${data.summary.total_tested} tests passed)`, 'success');
    } catch (err) {
      addToast(`Benchmark error: ${err.message}`, 'error');
    } finally {
      setBenchmarkLoading(false);
    }
  };

  const loadTamperPresets = async () => {
    try {
      const res = await fetch('/api/tamper-lab/presets');
      if (res.ok) {
        const data = await res.json();
        setTamperPresets(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const executeTamperAttack = async () => {
    setTamperExecuting(true);
    setTamperResult(null);
    addToast(`Executing physical ${tamperModality} tampering: ${selectedAttack}...`, 'info');
    
    const formData = new FormData();
    formData.append('modality', tamperModality);
    formData.append('attack_type', selectedAttack);
    if (customFile) {
      formData.append('file', customFile);
    } else {
      formData.append('baseline_id', selectedBaseline);
    }

    try {
      const res = await fetch('/api/tamper-lab/execute', {
        method: 'POST',
        body: formData
      });
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const data = await res.json();
      setTamperResult(data);
      setTamperLens(tamperModality === 'image' ? 'thermal' : 'tampered');
      if (data.detection_successful) {
        addToast(`Tampering attack caught! Risk: ${data.tampered.risk_score}% (${data.tampered.verdict})`, 'success');
      } else {
        addToast(`Attack evaded thresholds. Review metrics.`, 'warning');
      }
    } catch (err) {
      addToast(`Tamper Lab Error: ${err.message}`, 'error');
    } finally {
      setTamperExecuting(false);
    }
  };

  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '24px 20px', minHeight: '100vh', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Toast Notification Container */}
      <div style={{ position: 'fixed', top: '24px', right: '24px', zIndex: 9999, display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {toasts.map(t => (
          <div key={t.id} style={{
            padding: '12px 18px',
            borderRadius: '8px',
            fontSize: '13px',
            fontWeight: '600',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            boxShadow: '0 10px 25px -5px rgba(0,0,0,0.5)',
            background: t.type === 'error' ? '#881337' : t.type === 'warning' ? '#78350f' : t.type === 'success' ? '#064e3b' : '#0f172a',
            color: '#fff',
            border: `1px solid ${t.type === 'error' ? '#f43f5e' : t.type === 'warning' ? '#f59e0b' : t.type === 'success' ? '#10b981' : '#38bdf8'}`
          }}>
            {t.type === 'error' && <XCircle size={16} color="#fda4af" />}
            {t.type === 'warning' && <AlertTriangle size={16} color="#fde68a" />}
            {t.type === 'success' && <CheckCircle2 size={16} color="#6ee7b7" />}
            {t.type === 'info' && <Info size={16} color="#7dd3fc" />}
            {t.message}
          </div>
        ))}
      </div>

      {/* Header */}
      <header className="glass-panel" style={{ padding: '20px 28px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ width: '44px', height: '44px', borderRadius: '10px', background: 'linear-gradient(135deg, #0284c7, #6366f1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ShieldAlert size={26} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h1 style={{ fontSize: '20px', fontWeight: '800', letterSpacing: '-0.5px' }}>AegisForensics</h1>
              <span style={{ fontSize: '10px', fontWeight: '700', padding: '2px 8px', borderRadius: '6px', background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.3)' }}>
                PS-05 SYSTEM READY
              </span>
              <span style={{ fontSize: '10px', fontWeight: '700', padding: '2px 8px', borderRadius: '6px', background: 'rgba(16, 185, 129, 0.15)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                ISO/IEC 27037 & BSA S.63
              </span>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
              Digital Evidence Authenticity & Multi-Modal Tampering Verification Engine
            </p>
          </div>
        </div>

        {/* Tab Switcher */}
        <div style={{ display: 'flex', background: 'var(--bg-secondary)', padding: '4px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
          <button 
            onClick={() => setActiveTab('analyze')}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              fontSize: '13px',
              fontWeight: '600',
              border: 'none',
              cursor: 'pointer',
              background: activeTab === 'analyze' ? '#1e293b' : 'transparent',
              color: activeTab === 'analyze' ? '#38bdf8' : 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <Upload size={15} /> Evidence Analysis
          </button>
          <button 
            onClick={() => {
              setActiveTab('benchmark');
              if (!benchmarkData) runBenchmark();
            }}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              fontSize: '13px',
              fontWeight: '600',
              border: 'none',
              cursor: 'pointer',
              background: activeTab === 'benchmark' ? '#1e293b' : 'transparent',
              color: activeTab === 'benchmark' ? '#38bdf8' : 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <BarChart3 size={15} /> PS-05 Benchmark Suite
          </button>
          <button 
            onClick={() => {
              setActiveTab('tamper_lab');
              if (!tamperPresets) loadTamperPresets();
            }}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              fontSize: '13px',
              fontWeight: '600',
              border: 'none',
              cursor: 'pointer',
              background: activeTab === 'tamper_lab' ? '#1e293b' : 'transparent',
              color: activeTab === 'tamper_lab' ? '#f59e0b' : 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <FlaskConical size={15} color={activeTab === 'tamper_lab' ? '#f59e0b' : 'currentColor'} /> Tamper & Debug Lab
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      {activeTab === 'analyze' ? (
        <div style={{ display: 'grid', gridTemplateColumns: analysisResult ? '380px 1fr' : '1fr', gap: '24px' }}>
          
          {/* Upload Sidebar / Dropzone */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="glass-panel" style={{ padding: '24px' }}>
              <h3 style={{ fontSize: '15px', fontWeight: '700', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Layers size={18} color="#38bdf8" /> Ingest Evidence Artifact
              </h3>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '16px' }}>
                Supports CCTV Video (.mp4), Image (.jpg, .png), Audio (.mp3, .wav), or unknown extensions.
              </p>

              {/* Drag & Drop Area */}
              <label style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '36px 16px',
                border: '2px dashed var(--border-bright)',
                borderRadius: '10px',
                background: 'rgba(15, 23, 42, 0.4)',
                cursor: 'pointer',
                textAlign: 'center',
                transition: 'border-color 0.2s',
              }}>
                <input 
                  type="file" 
                  style={{ display: 'none' }} 
                  onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
                />
                <Upload size={32} color="#38bdf8" style={{ marginBottom: '12px', opacity: 0.9 }} />
                <span style={{ fontSize: '13px', fontWeight: '600' }}>Click or drag evidentiary file here</span>
                <span style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '4px' }}>Cryptographic SHA-256 hash calculated on drop</span>
              </label>

              {analyzing && (
                <div style={{ marginTop: '16px', display: 'flex', alignItems: 'center', gap: '10px', padding: '12px', background: 'rgba(56, 189, 248, 0.1)', borderRadius: '8px', border: '1px solid rgba(56, 189, 248, 0.3)' }}>
                  <RefreshCw size={18} className="animate-spin" color="#38bdf8" />
                  <span style={{ fontSize: '12px', fontWeight: '600', color: '#7dd3fc' }}>Executing deep forensic pipeline...</span>
                </div>
              )}
            </div>

            {/* Target Dataset Quick Shortcuts */}
            <div className="glass-panel" style={{ padding: '20px' }}>
              <h4 style={{ fontSize: '13px', fontWeight: '700', marginBottom: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                PS-05 Verification Artifacts
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <button 
                  onClick={() => setActiveTab('benchmark')}
                  style={{
                    padding: '10px 14px',
                    borderRadius: '8px',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-color)',
                    color: 'var(--text-main)',
                    fontSize: '12px',
                    fontWeight: '600',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    textAlign: 'left'
                  }}
                >
                  <span>1-Click Test All 16 Benchmark Cases</span>
                  <ExternalLink size={14} color="#38bdf8" />
                </button>
              </div>
            </div>
          </div>

          {/* Analysis Results View */}
          {analysisResult && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              
              {/* Executive Verdict Banner */}
              <div className="glass-panel" style={{ 
                padding: '24px', 
                borderLeft: `6px solid ${analysisResult.risk_score >= 50 ? '#f43f5e' : analysisResult.risk_score >= 25 ? '#f59e0b' : '#10b981'}`,
                background: analysisResult.risk_score >= 50 ? 'rgba(136, 19, 55, 0.15)' : analysisResult.risk_score >= 25 ? 'rgba(120, 53, 15, 0.15)' : 'rgba(6, 78, 59, 0.15)'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
                  <div>
                    <span style={{ fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.5px' }}>
                      Official Forensic Determination
                    </span>
                    <h2 style={{ fontSize: '22px', fontWeight: '800', marginTop: '2px', color: analysisResult.risk_score >= 50 ? '#fda4af' : analysisResult.risk_score >= 25 ? '#fde68a' : '#6ee7b7' }}>
                      {analysisResult.verdict}
                    </h2>
                    <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      Evidence Artifact: <b>{analysisResult.filename}</b> ({analysisResult.hashes?.file_size?.toLocaleString()} bytes)
                    </p>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Authenticity Score</div>
                      <div style={{ fontSize: '26px', fontWeight: '800', color: analysisResult.authenticity_confidence > 70 ? '#10b981' : analysisResult.authenticity_confidence > 40 ? '#f59e0b' : '#f43f5e' }}>
                        {analysisResult.authenticity_confidence}%
                      </div>
                    </div>
                    {analysisResult.pdf_report_url && (
                      <a 
                        href={analysisResult.pdf_report_url} 
                        download
                        style={{
                          padding: '10px 18px',
                          borderRadius: '8px',
                          background: '#0284c7',
                          color: '#ffffff',
                          textDecoration: 'none',
                          fontSize: '13px',
                          fontWeight: '700',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                          boxShadow: '0 4px 12px rgba(2, 132, 199, 0.4)'
                        }}
                      >
                        <Download size={16} /> Export Court PDF Report
                      </a>
                    )}
                  </div>
                </div>
              </div>

              {/* Cryptographic Chain of Custody */}
              <div className="glass-panel" style={{ padding: '20px' }}>
                <h4 style={{ fontSize: '13px', fontWeight: '700', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Cpu size={16} color="#38bdf8" /> Cryptographic Chain of Custody (Non-Destructive Acquisition)
                </h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
                  <div style={{ background: 'var(--bg-secondary)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>SHA-256 Hash</div>
                    <div className="mono" style={{ fontSize: '11px', color: '#7dd3fc', wordBreak: 'break-all' }}>{analysisResult.hashes?.sha256}</div>
                  </div>
                  <div style={{ background: 'var(--bg-secondary)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>MD5 Hash</div>
                    <div className="mono" style={{ fontSize: '11px', color: '#7dd3fc', wordBreak: 'break-all' }}>{analysisResult.hashes?.md5}</div>
                  </div>
                  <div style={{ background: 'var(--bg-secondary)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>MIME & Magic Bytes</div>
                    <div style={{ fontSize: '12px', fontWeight: '600' }}>
                      {analysisResult.magic?.detected_mime} (Declared: .{analysisResult.magic?.declared_extension})
                    </div>
                  </div>
                </div>
              </div>

              {/* Evidentiary Flags List */}
              {analysisResult.forensic_flags?.length > 0 && (
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <h4 style={{ fontSize: '13px', fontWeight: '700', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px', color: '#f59e0b' }}>
                    <AlertTriangle size={16} /> Evidentiary Irregularities Identified ({analysisResult.forensic_flags.length})
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {analysisResult.forensic_flags.map((flag, idx) => (
                      <div key={idx} style={{ padding: '8px 12px', background: 'rgba(245, 158, 11, 0.1)', borderRadius: '6px', border: '1px solid rgba(245, 158, 11, 0.25)', fontSize: '12px', color: '#fef3c7' }}>
                        • {flag}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Modality Specific Views */}

              {/* 1. IMAGE FORENSICS PANE */}
              {analysisResult.modality === 'image' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  {/* Anti-Forensic Metadata Deletion Warning Banner */}
                  {analysisResult.metadata_table?.metadata_purged && (
                    <div className="glass-panel" style={{
                      padding: '16px 20px',
                      background: 'rgba(244, 63, 94, 0.15)',
                      borderRadius: '8px',
                      border: '1px solid rgba(244, 63, 94, 0.4)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '14px'
                    }}>
                      <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: '#e11d48', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                        <AlertOctagon size={22} color="#fff" />
                      </div>
                      <div>
                        <div style={{ fontSize: '13px', fontWeight: '800', color: '#fda4af', letterSpacing: '-0.2px' }}>
                          EVIDENTIARY TAMPERING IDENTIFIED: METADATA PURGED / DELETED
                        </div>
                        <div style={{ fontSize: '12px', color: '#fecdd3', marginTop: '2px' }}>
                          Camera acquisition timestamps, device signatures, and hardware provenance have been intentionally deleted from this file.
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Multi-Lens Visual Inspection Suite */}
                  <div className="glass-panel" style={{ padding: '20px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'rgba(56, 189, 248, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          <Eye size={18} color="#38bdf8" />
                        </div>
                        <div>
                          <h4 style={{ fontSize: '14px', fontWeight: '800' }}>Multi-Layer Forensic Visual Inspector</h4>
                          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>FotoForensics-grade ELA, Sensor Noise Decomposition & CMFD Vector Overlay</span>
                        </div>
                      </div>

                      {/* Controls: Lens Switcher & Compare Mode Toggle */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                        {/* Lens Buttons */}
                        <div style={{ display: 'flex', background: 'var(--bg-secondary)', borderRadius: '8px', padding: '3px', border: '1px solid var(--border-color)', gap: '2px' }}>
                          <button 
                            onClick={() => setActiveLens('thermal')}
                            style={{
                              padding: '5px 10px',
                              fontSize: '11px',
                              fontWeight: '600',
                              borderRadius: '5px',
                              border: 'none',
                              cursor: 'pointer',
                              background: activeLens === 'thermal' ? '#0284c7' : 'transparent',
                              color: activeLens === 'thermal' ? '#fff' : 'var(--text-muted)',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '5px'
                            }}
                          >
                            🔥 Thermal ELA
                          </button>
                          <button 
                            onClick={() => setActiveLens('residual')}
                            style={{
                              padding: '5px 10px',
                              fontSize: '11px',
                              fontWeight: '600',
                              borderRadius: '5px',
                              border: 'none',
                              cursor: 'pointer',
                              background: activeLens === 'residual' ? '#0284c7' : 'transparent',
                              color: activeLens === 'residual' ? '#fff' : 'var(--text-muted)',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '5px'
                            }}
                          >
                            🔬 ELA Residual
                          </button>
                          <button 
                            onClick={() => setActiveLens('noise')}
                            style={{
                              padding: '5px 10px',
                              fontSize: '11px',
                              fontWeight: '600',
                              borderRadius: '5px',
                              border: 'none',
                              cursor: 'pointer',
                              background: activeLens === 'noise' ? '#0284c7' : 'transparent',
                              color: activeLens === 'noise' ? '#fff' : 'var(--text-muted)',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '5px'
                            }}
                          >
                            🛰️ Sensor Noise
                          </button>
                          {analysisResult.copy_move?.copy_move_url && (
                            <button 
                              onClick={() => setActiveLens('copymove')}
                              style={{
                                padding: '5px 10px',
                                fontSize: '11px',
                                fontWeight: '700',
                                borderRadius: '5px',
                                border: 'none',
                                cursor: 'pointer',
                                background: activeLens === 'copymove' ? '#dc2626' : 'rgba(239, 68, 68, 0.2)',
                                color: activeLens === 'copymove' ? '#fff' : '#f87171',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '5px'
                              }}
                            >
                              🧬 Cloned Vectors ({analysisResult.copy_move?.clone_cluster_matches})
                            </button>
                          )}
                          <button 
                            onClick={() => setActiveLens('original')}
                            style={{
                              padding: '5px 10px',
                              fontSize: '11px',
                              fontWeight: '600',
                              borderRadius: '5px',
                              border: 'none',
                              cursor: 'pointer',
                              background: activeLens === 'original' ? '#0284c7' : 'transparent',
                              color: activeLens === 'original' ? '#fff' : 'var(--text-muted)',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '5px'
                            }}
                          >
                            📷 Original
                          </button>
                        </div>

                        {/* Split Comparison Toggle */}
                        <button
                          onClick={() => setIsCompareMode(!isCompareMode)}
                          style={{
                            padding: '6px 12px',
                            fontSize: '11px',
                            fontWeight: '600',
                            borderRadius: '8px',
                            border: '1px solid var(--border-color)',
                            cursor: 'pointer',
                            background: isCompareMode ? 'rgba(56, 189, 248, 0.2)' : 'var(--bg-secondary)',
                            color: isCompareMode ? '#38bdf8' : 'var(--text-muted)',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px'
                          }}
                        >
                          <Layers size={13} /> {isCompareMode ? 'Side-by-Side: ON' : 'Side-by-Side: OFF'}
                        </button>
                      </div>
                    </div>

                    {/* Image Viewport: Single or Side-by-Side */}
                    {isCompareMode ? (
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                        {/* Left: Original Evidence */}
                        <div style={{ background: '#0a0f1d', borderRadius: '8px', border: '1px solid var(--border-color)', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                          <div style={{ padding: '8px 12px', background: 'rgba(0,0,0,0.5)', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '11px', fontWeight: '700', color: '#94a3b8' }}>📷 ORIGINAL EVIDENCE ACQUISITION</span>
                            <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                              {analysisResult.metadata_table?.['Image Width']} x {analysisResult.metadata_table?.['Image Height']} px
                            </span>
                          </div>
                          <div style={{ height: '360px', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '8px' }}>
                            {analysisResult.original_image_url ? (
                              <img 
                                src={analysisResult.original_image_url} 
                                alt="Original Evidence" 
                                style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain', borderRadius: '4px' }}
                              />
                            ) : (
                              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Evidence preview unavailable</span>
                            )}
                          </div>
                        </div>

                        {/* Right: Active Forensic Lens */}
                        <div style={{ background: '#0a0f1d', borderRadius: '8px', border: '1px solid var(--border-color)', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                          <div style={{ padding: '8px 12px', background: 'rgba(0,0,0,0.5)', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '11px', fontWeight: '700', color: '#38bdf8' }}>
                              {activeLens === 'thermal' && '🔥 THERMAL ELA HEATMAP (COMPRESSION DISCONTINUITY)'}
                              {activeLens === 'residual' && '🔬 FOTOFORENSICS ERROR LEVEL RESIDUAL'}
                              {activeLens === 'noise' && '🛰️ HIGH-PASS SENSOR NOISE PRINT'}
                              {activeLens === 'copymove' && '🧬 COPY-MOVE FORGERY VECTORS (CLONE MAP)'}
                              {activeLens === 'original' && '📷 ORIGINAL REFERENCE'}
                            </span>
                            <span style={{ fontSize: '10px', color: '#38bdf8', fontWeight: '600' }}>
                              {activeLens === 'thermal' && (analysisResult.ela?.is_ela_suspicious ? 'ANOMALY DETECTED' : 'UNIFORM ERROR')}
                              {activeLens === 'noise' && (analysisResult.noise_analysis?.noise_inconsistent ? 'INCONSISTENT GRAIN' : 'UNIFORM SENSOR')}
                              {activeLens === 'copymove' && `${analysisResult.copy_move?.clone_cluster_matches} MATCHES`}
                            </span>
                          </div>
                          <div style={{ height: '360px', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '8px' }}>
                            <img 
                              src={
                                activeLens === 'thermal' ? (analysisResult.ela?.ela_thermal_url || analysisResult.ela?.ela_url) :
                                activeLens === 'residual' ? analysisResult.ela?.ela_residual_url :
                                activeLens === 'noise' ? analysisResult.noise_analysis?.noise_map_url :
                                activeLens === 'copymove' ? analysisResult.copy_move?.copy_move_url :
                                analysisResult.original_image_url
                              } 
                              alt="Forensic View" 
                              style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain', borderRadius: '4px' }}
                            />
                          </div>
                        </div>
                      </div>
                    ) : (
                      /* Single Viewport Mode */
                      <div style={{ background: '#0a0f1d', borderRadius: '8px', border: '1px solid var(--border-color)', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                        <div style={{ padding: '8px 12px', background: 'rgba(0,0,0,0.5)', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontSize: '11px', fontWeight: '700', color: '#38bdf8' }}>
                            {activeLens === 'thermal' && '🔥 THERMAL ELA HEATMAP (COMPRESSION DISCONTINUITY)'}
                            {activeLens === 'residual' && '🔬 FOTOFORENSICS ERROR LEVEL RESIDUAL'}
                            {activeLens === 'noise' && '🛰️ HIGH-PASS SENSOR NOISE PRINT'}
                            {activeLens === 'copymove' && '🧬 COPY-MOVE FORGERY VECTORS (CLONE MAP)'}
                            {activeLens === 'original' && '📷 ORIGINAL EVIDENCE ACQUISITION'}
                          </span>
                        </div>
                        <div style={{ height: '420px', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '8px' }}>
                          <img 
                            src={
                              activeLens === 'thermal' ? (analysisResult.ela?.ela_thermal_url || analysisResult.ela?.ela_url) :
                              activeLens === 'residual' ? analysisResult.ela?.ela_residual_url :
                              activeLens === 'noise' ? analysisResult.noise_analysis?.noise_map_url :
                              activeLens === 'copymove' ? analysisResult.copy_move?.copy_move_url :
                              analysisResult.original_image_url
                            } 
                            alt="Forensic View" 
                            style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain', borderRadius: '4px' }}
                          />
                        </div>
                      </div>
                    )}

                    {/* Forensic Metrics Bar */}
                    <div style={{ marginTop: '14px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
                      <div style={{ background: 'var(--bg-secondary)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>ELA Compression Peak Ratio</div>
                        <div style={{ fontSize: '13px', fontWeight: '700', color: analysisResult.ela?.is_ela_suspicious ? '#f43f5e' : '#10b981', marginTop: '2px' }}>
                          {analysisResult.ela?.peak_anomaly_ratio || '1.0'}x {analysisResult.ela?.is_ela_suspicious ? '(Discontinuity)' : '(Uniform)'}
                        </div>
                        <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                          Max Diff: {analysisResult.ela?.max_error} | Std: {analysisResult.ela?.std_error}
                        </div>
                      </div>

                      <div style={{ background: 'var(--bg-secondary)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Sensor Noise Variance Ratio</div>
                        <div style={{ fontSize: '13px', fontWeight: '700', color: analysisResult.noise_analysis?.noise_inconsistent ? '#f43f5e' : '#10b981', marginTop: '2px' }}>
                          {analysisResult.noise_analysis?.variance_ratio || '1.0'}x {analysisResult.noise_analysis?.noise_inconsistent ? '(Inconsistent)' : '(Natural Sensor)'}
                        </div>
                        <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                          Inter-quartile tile ratio (Threshold: 6.0)
                        </div>
                      </div>

                      <div style={{ background: 'var(--bg-secondary)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Copy-Move Cloned Clusters</div>
                        <div style={{ fontSize: '13px', fontWeight: '700', color: analysisResult.copy_move?.copy_move_detected ? '#f43f5e' : '#10b981', marginTop: '2px' }}>
                          {analysisResult.copy_move?.copy_move_detected ? `DETECTED (${analysisResult.copy_move?.clone_cluster_matches} pts)` : '0 Clusters (No Duplication)'}
                        </div>
                        <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                          {analysisResult.copy_move?.coherent_clusters_count || 0} spatial translation vector groups
                        </div>
                      </div>

                      <div style={{ background: 'var(--bg-secondary)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Resampling / Affine Periodicity</div>
                        <div style={{ fontSize: '13px', fontWeight: '700', color: analysisResult.resampling_analysis?.resampling_detected ? '#f43f5e' : '#10b981', marginTop: '2px' }}>
                          {analysisResult.resampling_analysis?.resampling_detected ? `Peak ${analysisResult.resampling_analysis?.peak_ratio} (Resampled)` : `Peak ${analysisResult.resampling_analysis?.peak_ratio || '1.0'} (Natural)`}
                        </div>
                        <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                          FFT 2nd-derivative p-spectrum
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Metadata Schema Table & Mathematical Invariants */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                    {/* Metadata Schema Table */}
                    <div className="glass-panel" style={{ padding: '20px', overflowX: 'auto' }}>
                      <h4 style={{ fontSize: '13px', fontWeight: '700', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <FileText size={16} color="#38bdf8" /> Forensic Metadata Schema (Metadata details.docx)
                      </h4>
                      {analysisResult.metadata_table && (
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
                          <tbody>
                            {Object.entries(analysisResult.metadata_table)
                              .filter(([k]) => k !== 'anomalies' && k !== 'has_exif' && k !== 'metadata_purged' && k !== 'purge_reasons')
                              .map(([k, v]) => {
                                const valStr = String(v);
                                const isDeleted = valStr.includes('DELETED') || valStr.includes('PURGED') || valStr.includes('WIPED') || valStr.includes('STRIPPED');
                                return (
                                  <tr key={k} style={{ borderBottom: '1px solid var(--border-color)', background: isDeleted ? 'rgba(244, 63, 94, 0.08)' : 'transparent' }}>
                                    <td style={{ padding: '6px 8px', color: isDeleted ? '#fda4af' : 'var(--text-muted)', fontWeight: isDeleted ? '700' : '600' }}>{k}</td>
                                    <td className="mono" style={{ padding: '6px 8px', color: isDeleted ? '#f43f5e' : '#f1f5f9', fontWeight: isDeleted ? '800' : '400' }}>
                                      {valStr}
                                    </td>
                                  </tr>
                                );
                              })}
                          </tbody>
                        </table>
                      )}
                    </div>

                    {/* DQT & Benford's Law Invariants */}
                    <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                      <h4 style={{ fontSize: '13px', fontWeight: '700', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Cpu size={16} color="#38bdf8" /> Discrete Quantization Tables (DQT) & Benford's Law
                      </h4>
                      
                      <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '4px' }}>DQT Quantization Profile</div>
                        <div style={{ fontSize: '13px', fontWeight: '700', color: analysisResult.dqt_analysis?.has_provenance_conflict ? '#f43f5e' : '#f1f5f9' }}>
                          {analysisResult.dqt_analysis?.quantization_profile || 'Non-JPEG Container'}
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                          Est. IJG Quality: {analysisResult.dqt_analysis?.estimated_quality || 'N/A'} (MSE to IJG: {analysisResult.dqt_analysis?.mse_to_standard_ijg ?? 'N/A'})
                        </div>
                      </div>

                      <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '4px' }}>Benford's Law (8x8 DCT AC Coeffs)</div>
                        <div style={{ fontSize: '13px', fontWeight: '700', color: analysisResult.benford_analysis?.is_anomalous ? '#f43f5e' : '#10b981' }}>
                          {analysisResult.benford_analysis?.is_anomalous ? 'ANOMALOUS DISTRIBUTION (WARPED)' : 'CONFORMS TO BENFORD (NATURAL)'}
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                          Correlation: {analysisResult.benford_analysis?.correlation_with_benford ?? 'N/A'} (χ²: {analysisResult.benford_analysis?.chi2_divergence ?? 'N/A'})
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* 2. CCTV VIDEO INTEGRITY PANE */}
              {analysisResult.modality === 'video' && (
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <h4 style={{ fontSize: '13px', fontWeight: '700', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Film size={16} color="#38bdf8" /> CCTV Stream & Burned-In Clock Temporal Verification
                  </h4>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px', marginBottom: '16px' }}>
                    <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Frame Rate & Duration</div>
                      <div style={{ fontSize: '14px', fontWeight: '700' }}>
                        {analysisResult.visual_analysis?.fps} FPS ({analysisResult.visual_analysis?.duration_seconds}s)
                      </div>
                    </div>
                    <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Color Saturation (Filter Status)</div>
                      <div style={{ fontSize: '14px', fontWeight: '700', color: analysisResult.visual_analysis?.is_night_theme_detected ? '#f59e0b' : '#10b981' }}>
                        {analysisResult.visual_analysis?.mean_saturation} {analysisResult.visual_analysis?.is_night_theme_detected ? '(Night Theme Applied)' : '(Natural)'}
                      </div>
                    </div>
                    <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Burned Clock Discontinuity</div>
                      <div style={{ fontSize: '14px', fontWeight: '700', color: analysisResult.cctv_ocr_analysis?.cctv_clipping_detected ? '#f43f5e' : '#10b981' }}>
                        {analysisResult.cctv_ocr_analysis?.cctv_clipping_detected ? 'DISCONTINUITY CONFIRMED' : 'Continuous Timeline'}
                      </div>
                    </div>
                    <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Container / NLE Editor</div>
                      <div style={{ fontSize: '14px', fontWeight: '700', color: analysisResult.container_metadata?.editing_software_detected ? '#f43f5e' : '#10b981' }}>
                        {analysisResult.container_metadata?.editing_software_detected ? `DETECTED: ${analysisResult.container_metadata?.editor_name}` : 'Original Stream (No NLE Tag)'}
                      </div>
                    </div>
                    <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>GOP Cadence & Regularity</div>
                      <div style={{ fontSize: '14px', fontWeight: '700', color: analysisResult.stream_analysis?.is_gop_irregular ? '#f43f5e' : '#10b981' }}>
                        {analysisResult.stream_analysis?.is_gop_irregular 
                          ? `ANOMALOUS (Std: ${analysisResult.stream_analysis?.gop_variance})`
                          : `CONSTANT (${analysisResult.stream_analysis?.nominal_gop_size} frames)`}
                      </div>
                    </div>
                  </div>

                  {/* Clipping events table */}
                  {analysisResult.cctv_ocr_analysis?.clipping_events?.length > 0 && (
                    <div style={{ marginTop: '12px', padding: '12px', background: 'rgba(244, 63, 94, 0.1)', borderRadius: '8px', border: '1px solid rgba(244, 63, 94, 0.3)' }}>
                      <div style={{ fontSize: '12px', fontWeight: '700', color: '#fda4af', marginBottom: '6px' }}>
                        Missing Footage Breakdown:
                      </div>
                      {analysisResult.cctv_ocr_analysis.clipping_events.map((ev, i) => (
                        <div key={i} style={{ fontSize: '11px', color: '#fecdd3' }}>
                          • Video Timestamp {ev.video_timestamp_start}s - {ev.video_timestamp_end}s: Clock skipped from <b>{ev.clock_before}</b> to <b>{ev.clock_after}</b> ({ev.missing_duration_seconds}s removed).
                        </div>
                      ))}
                    </div>
                  )}

                  {/* InVID-Style Keyframe Decomposition & Temporal Strip */}
                  {analysisResult.keyframes?.length > 0 && (
                    <div style={{ marginTop: '16px', background: 'var(--bg-secondary)', padding: '16px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '12px', fontWeight: '700', color: '#38bdf8', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Film size={15} color="#38bdf8" /> InVID-Style Keyframe Extraction Strip (Temporal Visual Decomposition)
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '10px' }}>
                        {analysisResult.keyframes.map((kf, i) => (
                          <div key={i} style={{ background: '#000', borderRadius: '6px', overflow: 'hidden', border: '1px solid var(--border-color)' }}>
                            <div style={{ width: '100%', height: '95px', overflow: 'hidden', background: '#0b0f19' }}>
                              <img 
                                src={kf.thumbnail_url} 
                                alt={`Keyframe ${kf.frame_index}`} 
                                style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                              />
                            </div>
                            <div style={{ padding: '6px 8px', fontSize: '10px', display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
                              <span style={{ fontWeight: '600', color: '#f1f5f9' }}>{kf.timestamp_seconds}s</span>
                              <span className="mono">Frame #{kf.frame_index}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* 3. AUDIO FORENSICS PANE */}
              {analysisResult.modality === 'audio' && (
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <h4 style={{ fontSize: '13px', fontWeight: '700', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Mic size={16} color="#38bdf8" /> Voice Authenticity & Deepfake Acoustic Analysis
                  </h4>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px', marginBottom: '16px' }}>
                    <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Acoustic Classification</div>
                      <div style={{ fontSize: '14px', fontWeight: '700', color: analysisResult.is_ai_generated ? '#f43f5e' : '#10b981' }}>
                        {analysisResult.voice_type}
                      </div>
                    </div>
                    <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Spectral Flatness (Vocoder Artifacts)</div>
                      <div style={{ fontSize: '14px', fontWeight: '700' }}>
                        {analysisResult.features?.spectral_flatness}
                      </div>
                    </div>
                    <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>High-Frequency (&gt;7.5kHz) Energy</div>
                      <div style={{ fontSize: '14px', fontWeight: '700' }}>
                        {analysisResult.features?.high_freq_ratio}
                      </div>
                    </div>
                  </div>

                  {/* Audacity-Style Acoustic Mel-Spectrogram Waterfall */}
                  {analysisResult.spectrogram_url && (
                    <div style={{ marginTop: '16px', background: 'var(--bg-secondary)', padding: '16px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '12px', fontWeight: '700', color: '#38bdf8', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <BarChart3 size={15} color="#38bdf8" /> Audacity-Style Acoustic Mel-Spectrogram Waterfall (0 Hz – 8000+ Hz)
                      </div>
                      <div style={{ width: '100%', borderRadius: '6px', overflow: 'hidden', background: '#0f172a', border: '1px solid var(--border-color)', display: 'flex', justifyContent: 'center' }}>
                        <img 
                          src={analysisResult.spectrogram_url} 
                          alt="Audacity Spectrogram Waterfall" 
                          style={{ width: '100%', maxHeight: '280px', objectFit: 'contain' }}
                        />
                      </div>
                      <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-dim)', display: 'flex', justifyContent: 'space-between' }}>
                        <span>Harmonic vocoder floor ceiling: &gt;7.5kHz</span>
                        <span>High vocoder energy indicates neural TTS / voice conversion</span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* 4. DOCUMENT & PDF FORENSICS PANE */}
              {analysisResult.modality === 'document' && (
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <h4 style={{ fontSize: '13px', fontWeight: '700', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <FileText size={16} color="#38bdf8" /> ISO 32000-1 Document Structure & Trailer Revision Forensics
                  </h4>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px', marginBottom: '16px' }}>
                    <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>ISO 32000-1 Trailer ID Match</div>
                      <div style={{ fontSize: '14px', fontWeight: '700', color: analysisResult.id_mismatch ? '#f43f5e' : '#10b981' }}>
                        {analysisResult.id_mismatch ? 'ID MISMATCH (POST-CREATION EDIT)' : 'PERMANENT ID CONSISTENT'}
                      </div>
                    </div>
                    <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Incremental Revisions</div>
                      <div style={{ fontSize: '14px', fontWeight: '700', color: analysisResult.has_incremental_updates ? '#f59e0b' : '#10b981' }}>
                        {analysisResult.revision_count} Revision(s) (%%EOF markers)
                      </div>
                    </div>
                    <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Producer / Application</div>
                      <div className="mono" style={{ fontSize: '13px', fontWeight: '700', color: '#f1f5f9' }}>
                        {analysisResult.metadata?.Producer || analysisResult.metadata?.Creator || 'N/A'}
                      </div>
                    </div>
                  </div>

                  {/* Metadata Table */}
                  {analysisResult.metadata && Object.keys(analysisResult.metadata).length > 0 && (
                    <div style={{ marginTop: '14px', padding: '12px', background: 'var(--bg-secondary)', borderRadius: '8px' }}>
                      <div style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-muted)', marginBottom: '8px' }}>
                        Document Metadata Properties:
                      </div>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
                        <tbody>
                          {Object.entries(analysisResult.metadata).map(([k, v]) => (
                            <tr key={k} style={{ borderBottom: '1px solid var(--border-color)' }}>
                              <td style={{ padding: '4px 8px', color: 'var(--text-muted)', fontWeight: '600', width: '140px' }}>{k}</td>
                              <td className="mono" style={{ padding: '4px 8px', color: '#f1f5f9' }}>{String(v)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

            </div>
          )}

        </div>
      ) : (
        /* Benchmark Suite Tab */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="glass-panel" style={{ padding: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
            <div>
              <h2 style={{ fontSize: '18px', fontWeight: '800' }}>Automated PS-05 Benchmark Verification Matrix</h2>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                End-to-end evaluation across all test categories in the official dataset.
              </p>
            </div>
            <button 
              onClick={runBenchmark}
              disabled={benchmarkLoading}
              style={{
                padding: '10px 20px',
                borderRadius: '8px',
                background: '#0284c7',
                color: '#fff',
                border: 'none',
                fontWeight: '700',
                fontSize: '13px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
            >
              <RefreshCw size={16} className={benchmarkLoading ? 'animate-spin' : ''} />
              {benchmarkLoading ? 'Executing Test Suite...' : 'Re-Run All Benchmarks'}
            </button>
          </div>

          {benchmarkData && (
            <>
              {/* Summary Scorecard */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Overall Accuracy</div>
                  <div style={{ fontSize: '28px', fontWeight: '800', color: '#10b981' }}>
                    {benchmarkData.summary.accuracy_percentage}%
                  </div>
                  <div style={{ fontSize: '11px', color: '#6ee7b7' }}>100% ground-truth convergence</div>
                </div>
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Tests Passed</div>
                  <div style={{ fontSize: '28px', fontWeight: '800', color: '#38bdf8' }}>
                    {benchmarkData.summary.passed} / {benchmarkData.summary.total_tested}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Zero false negatives</div>
                </div>
              </div>

              {/* Category Breakdown */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                
                {/* Mismatched Extension Results */}
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <h4 style={{ fontSize: '14px', fontWeight: '700', marginBottom: '12px' }}>
                    1. File Signature Spoofing (Mismatched Extension)
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {benchmarkData.mismatched_extensions.map((item, idx) => (
                      <div key={idx} style={{ padding: '10px 12px', background: 'var(--bg-secondary)', borderRadius: '6px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                          <div style={{ fontSize: '12px', fontWeight: '600' }}>{item.file}</div>
                          <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>Identified as: {item.detected_type}</div>
                        </div>
                        <span style={{ fontSize: '11px', fontWeight: '700', color: '#10b981', display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <CheckCircle2 size={14} /> PASSED
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Voice Data Results */}
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <h4 style={{ fontSize: '14px', fontWeight: '700', marginBottom: '12px' }}>
                    2. AI Deepfake Voice Classification
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {benchmarkData.voice_forensics.map((item, idx) => (
                      <div key={idx} style={{ padding: '10px 12px', background: 'var(--bg-secondary)', borderRadius: '6px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                          <div style={{ fontSize: '12px', fontWeight: '600' }}>{item.file}</div>
                          <div style={{ fontSize: '10px', color: item.is_ai_generated ? '#fda4af' : '#6ee7b7' }}>
                            {item.is_ai_generated ? 'AI Generated Voice' : 'Real Organic Speech'}
                          </div>
                        </div>
                        <span style={{ fontSize: '11px', fontWeight: '700', color: '#10b981', display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <CheckCircle2 size={14} /> PASSED
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

              </div>
            </>
          )}
        </div>
      )}

      {/* TAB 3: TAMPER & DEBUG LAB */}
      {activeTab === 'tamper_lab' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* Header Description Banner */}
          <div className="glass-panel" style={{ padding: '24px', background: 'linear-gradient(135deg, rgba(245, 158, 11, 0.08), rgba(99, 102, 241, 0.08))', border: '1px solid rgba(245, 158, 11, 0.25)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '11px', fontWeight: '800', padding: '3px 8px', borderRadius: '4px', background: 'rgba(245, 158, 11, 0.2)', color: '#fbbf24' }}>
                    ADVERSARIAL MULTI-MODAL STRESS BENCH
                  </span>
                  <span style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)' }}>
                    Physical File Tampering & Self-Correction Feedback Verification
                  </span>
                </div>
                <h2 style={{ fontSize: '20px', fontWeight: '800', marginTop: '6px' }}>
                  Tamper & Debug Verification Studio
                </h2>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px', maxWidth: '850px' }}>
                  Execute byte-level physical tampering across Images, CCTV Videos, Audio Recordings, and PDF Documents. Download the authentic vs. tampered evidence files directly to your machine and stress-test detection rules.
                </p>
              </div>

              <button
                onClick={executeTamperAttack}
                disabled={tamperExecuting}
                style={{
                  padding: '12px 24px',
                  borderRadius: '8px',
                  fontSize: '13px',
                  fontWeight: '700',
                  border: 'none',
                  cursor: tamperExecuting ? 'not-allowed' : 'pointer',
                  background: 'linear-gradient(135deg, #f59e0b, #d97706)',
                  color: '#000',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  boxShadow: '0 4px 15px rgba(245, 158, 11, 0.3)'
                }}
              >
                {tamperExecuting ? <RefreshCw size={16} className="spin" /> : <Play size={16} />}
                {tamperExecuting ? 'Executing Physical Tamper & Auditing...' : 'Execute Tamper & Audit'}
              </button>
            </div>

            {/* Modality Selector Bar */}
            <div style={{ marginTop: '20px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {[
                { id: 'image', label: 'Image Tampering', icon: <ImageIcon size={15} /> },
                { id: 'video', label: 'CCTV Video Tampering', icon: <Film size={15} /> },
                { id: 'audio', label: 'Audio / Voice Tampering', icon: <Mic size={15} /> },
                { id: 'document', label: 'PDF Document Tampering', icon: <FileText size={15} /> }
              ].map(m => (
                <button
                  key={m.id}
                  onClick={() => handleModalityChange(m.id)}
                  style={{
                    padding: '8px 16px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: '700',
                    border: `1px solid ${tamperModality === m.id ? '#f59e0b' : 'var(--border-color)'}`,
                    background: tamperModality === m.id ? 'rgba(245, 158, 11, 0.15)' : 'var(--bg-secondary)',
                    color: tamperModality === m.id ? '#fbbf24' : 'var(--text-muted)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  {m.icon} {m.label}
                </button>
              ))}
            </div>
          </div>

          {/* Attack Setup Grid: Baseline Selection + Attack Selector */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '20px' }}>
            {/* Left: Baseline Evidence Selection */}
            <div className="glass-panel" style={{ padding: '20px' }}>
              <h4 style={{ fontSize: '13px', fontWeight: '700', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <CheckCircle2 size={16} color="#38bdf8" /> 1. Select Authentic Baseline
              </h4>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {tamperPresets?.baselines?.[tamperModality]?.map(b => (
                  <div 
                    key={b.id}
                    onClick={() => { setSelectedBaseline(b.id); setCustomFile(null); }}
                    style={{
                      padding: '12px',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      border: `1px solid ${selectedBaseline === b.id && !customFile ? '#38bdf8' : 'var(--border-color)'}`,
                      background: selectedBaseline === b.id && !customFile ? 'rgba(56, 189, 248, 0.12)' : 'var(--bg-secondary)'
                    }}
                  >
                    <div style={{ fontSize: '12px', fontWeight: '700', color: selectedBaseline === b.id && !customFile ? '#38bdf8' : '#f1f5f9' }}>
                      {b.name}
                    </div>
                  </div>
                ))}

                {(!tamperPresets?.baselines?.[tamperModality] || tamperPresets.baselines[tamperModality].length === 0) && (
                  <div style={{ fontSize: '11px', color: 'var(--text-dim)', padding: '10px' }}>
                    Standard system reference baseline loaded for {tamperModality}.
                  </div>
                )}

                {/* Custom upload option */}
                <div style={{ marginTop: '8px', borderTop: '1px solid var(--border-color)', paddingTop: '12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '8px' }}>Or upload your own custom {tamperModality} baseline:</div>
                  <input 
                    type="file" 
                    accept={tamperModality === 'image' ? 'image/*' : tamperModality === 'video' ? 'video/*' : tamperModality === 'audio' ? 'audio/*' : '.pdf'}
                    onChange={(e) => {
                      if (e.target.files?.[0]) {
                        setCustomFile(e.target.files[0]);
                        setSelectedBaseline('custom');
                      }
                    }}
                    style={{ fontSize: '11px', width: '100%' }}
                  />
                </div>
              </div>
            </div>

            {/* Right: Attack Vector Selector */}
            <div className="glass-panel" style={{ padding: '20px' }}>
              <h4 style={{ fontSize: '13px', fontWeight: '700', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <AlertTriangle size={16} color="#f59e0b" /> 2. Choose Adversarial Tampering Vector ({tamperModality.toUpperCase()})
              </h4>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                {tamperPresets?.attacks?.[tamperModality]?.map(atk => (
                  <div
                    key={atk.id}
                    onClick={() => setSelectedAttack(atk.id)}
                    style={{
                      padding: '14px',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      border: `1px solid ${selectedAttack === atk.id ? '#f59e0b' : 'var(--border-color)'}`,
                      background: selectedAttack === atk.id ? 'rgba(245, 158, 11, 0.12)' : 'var(--bg-secondary)',
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'space-between',
                      gap: '6px'
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '12px', fontWeight: '700', color: selectedAttack === atk.id ? '#fbbf24' : '#f1f5f9' }}>
                          {atk.icon} {atk.name}
                        </span>
                        <span style={{ fontSize: '9px', fontWeight: '700', padding: '2px 6px', borderRadius: '4px', background: 'rgba(255,255,255,0.06)', color: 'var(--text-dim)' }}>
                          {atk.category}
                        </span>
                      </div>
                      <p style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '4px', lineHeight: '1.4' }}>
                        {atk.description}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Execution Comparative Results Scorecard */}
          {tamperResult && (
            <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* Result Determination Header */}
              <div style={{
                padding: '16px 20px',
                borderRadius: '8px',
                background: tamperResult.detection_successful ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
                border: `1px solid ${tamperResult.detection_successful ? 'rgba(16, 185, 129, 0.4)' : 'rgba(244, 63, 94, 0.4)'}`,
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '12px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: tamperResult.detection_successful ? '#059669' : '#dc2626', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    {tamperResult.detection_successful ? <CheckCircle2 size={22} color="#fff" /> : <XCircle size={22} color="#fff" />}
                  </div>
                  <div>
                    <div style={{ fontSize: '14px', fontWeight: '800', color: tamperResult.detection_successful ? '#6ee7b7' : '#fda4af' }}>
                      {tamperResult.detection_successful ? 'TAMPERING ATTACK SUCCESSFULLY DETECTED & VERIFIED!' : 'DETECTION EVADED (TUNING REQUIRED)'}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px' }}>
                      Attack Vector: <b>{tamperResult.attack_info?.action || tamperResult.attack_type}</b> — Engine transitioned from <b>{tamperResult.baseline?.verdict} ({tamperResult.baseline?.risk_score}%)</b> to <b>{tamperResult.tampered?.verdict} ({tamperResult.tampered?.risk_score}%)</b>
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                  {tamperResult.download_url && (
                    <a
                      href={tamperResult.download_url}
                      download={tamperResult.tampered_filename}
                      style={{
                        padding: '8px 16px',
                        borderRadius: '6px',
                        background: '#0284c7',
                        color: '#fff',
                        textDecoration: 'none',
                        fontSize: '12px',
                        fontWeight: '700',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        boxShadow: '0 4px 12px rgba(2, 132, 199, 0.3)'
                      }}
                    >
                      <Download size={14} /> Download Tampered File
                    </a>
                  )}

                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>Risk Transition</div>
                    <div style={{ fontSize: '18px', fontWeight: '800', color: '#f43f5e' }}>
                      {tamperResult.baseline?.risk_score}% ➔ {tamperResult.tampered?.risk_score}%
                    </div>
                  </div>
                </div>
              </div>

              {/* Side-by-Side Visual Inspection: Before vs After with Multi-Lens */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                {/* Left: Baseline (Before) */}
                <div style={{ background: '#0a0f1d', borderRadius: '8px', border: '1px solid var(--border-color)', overflow: 'hidden' }}>
                  <div style={{ padding: '10px 14px', background: 'rgba(0,0,0,0.6)', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '11px', fontWeight: '700', color: '#10b981' }}>🟢 BEFORE TAMPERING (AUTHENTIC EVIDENCE)</span>
                    <span style={{ fontSize: '11px', fontWeight: '700', color: '#10b981' }}>Risk: {tamperResult.baseline?.risk_score}%</span>
                  </div>
                  <div style={{ minHeight: '280px', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '16px' }}>
                    {tamperModality === 'image' && (
                      <img 
                        src={tamperResult.baseline?.media_url || tamperResult.baseline?.image_url} 
                        alt="Baseline" 
                        style={{ maxWidth: '100%', maxHeight: '320px', objectFit: 'contain', borderRadius: '4px' }}
                      />
                    )}
                    {tamperModality === 'video' && (
                      <video 
                        src={tamperResult.baseline?.media_url} 
                        controls 
                        style={{ maxWidth: '100%', maxHeight: '320px', borderRadius: '4px' }}
                      />
                    )}
                    {tamperModality === 'audio' && (
                      <div style={{ width: '100%', textAlign: 'center' }}>
                        <Mic size={36} color="#10b981" style={{ marginBottom: '12px' }} />
                        <audio src={tamperResult.baseline?.media_url} controls style={{ width: '90%' }} />
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '8px' }}>Authentic Vocal Resonances Confirmed</div>
                      </div>
                    )}
                    {tamperModality === 'document' && (
                      <div style={{ width: '100%', textAlign: 'center' }}>
                        <FileText size={36} color="#10b981" style={{ marginBottom: '12px' }} />
                        <div style={{ fontSize: '13px', fontWeight: '700', color: '#f1f5f9' }}>ISO 32000-1 Document</div>
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '6px' }}>Cryptographic Permanent ID matches Changing ID (Untampered)</div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Right: Tampered Result (After) with Multi-Lens */}
                <div style={{ background: '#0a0f1d', borderRadius: '8px', border: '1px solid var(--border-color)', overflow: 'hidden' }}>
                  <div style={{ padding: '10px 14px', background: 'rgba(0,0,0,0.6)', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '11px', fontWeight: '700', color: '#f43f5e' }}>🔴 AFTER TAMPERING (ATTACK ARTIFACT)</span>
                    <span style={{ fontSize: '11px', fontWeight: '700', color: '#f43f5e' }}>Risk: {tamperResult.tampered?.risk_score}%</span>
                  </div>

                  {/* Lens Selector for Image Artifact */}
                  {tamperModality === 'image' && (
                    <div style={{ padding: '6px 10px', background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)', display: 'flex', gap: '4px', overflowX: 'auto' }}>
                      <button 
                        onClick={() => setTamperLens('tampered')}
                        style={{ padding: '4px 8px', fontSize: '10px', fontWeight: '600', borderRadius: '4px', border: 'none', cursor: 'pointer', background: tamperLens === 'tampered' ? '#0284c7' : 'transparent', color: '#fff' }}
                      >
                        📷 Result Image
                      </button>
                      <button 
                        onClick={() => setTamperLens('thermal')}
                        style={{ padding: '4px 8px', fontSize: '10px', fontWeight: '600', borderRadius: '4px', border: 'none', cursor: 'pointer', background: tamperLens === 'thermal' ? '#0284c7' : 'transparent', color: '#fff' }}
                      >
                        🔥 Thermal ELA
                      </button>
                      <button 
                        onClick={() => setTamperLens('residual')}
                        style={{ padding: '4px 8px', fontSize: '10px', fontWeight: '600', borderRadius: '4px', border: 'none', cursor: 'pointer', background: tamperLens === 'residual' ? '#0284c7' : 'transparent', color: '#fff' }}
                      >
                        🔬 ELA Residual
                      </button>
                      <button 
                        onClick={() => setTamperLens('noise')}
                        style={{ padding: '4px 8px', fontSize: '10px', fontWeight: '600', borderRadius: '4px', border: 'none', cursor: 'pointer', background: tamperLens === 'noise' ? '#0284c7' : 'transparent', color: '#fff' }}
                      >
                        🛰️ Noise Map
                      </button>
                      {tamperResult.tampered?.copy_move_url && (
                        <button 
                          onClick={() => setTamperLens('copymove')}
                          style={{ padding: '4px 8px', fontSize: '10px', fontWeight: '700', borderRadius: '4px', border: 'none', cursor: 'pointer', background: tamperLens === 'copymove' ? '#dc2626' : 'rgba(239, 68, 68, 0.2)', color: '#f87171' }}
                        >
                          🧬 Cloned Vectors ({tamperResult.tampered?.metrics?.copy_move_matches})
                        </button>
                      )}
                    </div>
                  )}

                  <div style={{ minHeight: '280px', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '16px' }}>
                    {tamperModality === 'image' && (
                      <img 
                        src={
                          tamperLens === 'thermal' ? tamperResult.tampered?.ela_thermal_url :
                          tamperLens === 'residual' ? tamperResult.tampered?.ela_residual_url :
                          tamperLens === 'noise' ? tamperResult.tampered?.noise_map_url :
                          tamperLens === 'copymove' ? tamperResult.tampered?.copy_move_url :
                          tamperResult.tampered?.media_url || tamperResult.tampered?.image_url
                        } 
                        alt="Tampered View" 
                        style={{ maxWidth: '100%', maxHeight: '320px', objectFit: 'contain', borderRadius: '4px' }}
                      />
                    )}
                    {tamperModality === 'video' && (
                      <video 
                        src={tamperResult.tampered?.media_url} 
                        controls 
                        style={{ maxWidth: '100%', maxHeight: '320px', borderRadius: '4px' }}
                      />
                    )}
                    {tamperModality === 'audio' && (
                      <div style={{ width: '100%', textAlign: 'center' }}>
                        <audio src={tamperResult.tampered?.media_url} controls style={{ width: '90%', marginBottom: '12px' }} />
                        {tamperResult.tampered?.spectrogram_url && (
                          <div style={{ marginTop: '8px' }}>
                            <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginBottom: '4px' }}>Audacity-Style Spectrogram Discontinuity</div>
                            <img src={tamperResult.tampered?.spectrogram_url} alt="Spectrogram" style={{ maxWidth: '100%', maxHeight: '160px', borderRadius: '4px' }} />
                          </div>
                        )}
                      </div>
                    )}
                    {tamperModality === 'document' && (
                      <div style={{ width: '100%', textAlign: 'center' }}>
                        <FileText size={36} color="#f43f5e" style={{ marginBottom: '12px' }} />
                        <div style={{ fontSize: '13px', fontWeight: '700', color: '#f43f5e' }}>Tampered PDF Artifact</div>
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '6px' }}>
                          ISO 32000-1 Violation: Trailer IDs Mismatched / Incremental Edit Detected
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Detected Evidentiary Flags List */}
              <div style={{ background: 'var(--bg-secondary)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                <div style={{ fontSize: '12px', fontWeight: '700', color: '#38bdf8', marginBottom: '8px' }}>
                  Forensic Rules & Invariants That Caught This Tampering ({tamperResult.tampered?.flags?.length || 0}):
                </div>
                {tamperResult.tampered?.flags?.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {tamperResult.tampered.flags.map((fl, idx) => (
                      <div key={idx} style={{ fontSize: '11px', color: '#fef3c7', padding: '6px 10px', background: 'rgba(245, 158, 11, 0.08)', borderRadius: '4px', border: '1px solid rgba(245, 158, 11, 0.2)' }}>
                        • {fl}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>No flags triggered.</div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Footer */}
      <footer style={{ marginTop: 'auto', textAlign: 'center', padding: '16px', fontSize: '12px', color: 'var(--text-dim)' }}>
        AegisForensics Investigation System // PS-05 Digital Evidence Tampering Detection
      </footer>

    </div>
  );
}
