import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_URL = 'http://localhost:5001/api';

function App() {
    const [url, setUrl] = useState('https://example.com');
    const [crawlDepth, setCrawlDepth] = useState(3);
    const [isScanning, setIsScanning] = useState(false);
    const [currentScanId, setCurrentScanId] = useState(null);
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);
    const [isConnected, setIsConnected] = useState(false);
    const [showHelp, setShowHelp] = useState(false);

    useEffect(() => {
        const checkConnection = async () => {
            try {
                await axios.get(`${API_URL}/status`);
                setIsConnected(true);
                setError(null);
            } catch (err) {
                setIsConnected(false);
                setError('Cannot connect to scanner server. Make sure Python backend is running on port 5001.');
            }
        };

        checkConnection();
        const interval = setInterval(checkConnection, 5000);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        if (!currentScanId || !isScanning) return;

        const pollResults = async () => {
            try {
                const response = await axios.get(`${API_URL}/scan/${currentScanId}`);

                if (response.data.status === 'completed' || response.data.findings) {
                    setResults(response.data);
                    setIsScanning(false);
                } else if (response.data.status === 'failed') {
                    setError('Scan failed: ' + (response.data.error || 'Unknown error'));
                    setIsScanning(false);
                }
            } catch (err) {
                console.error('Polling error:', err);
            }
        };

        const interval = setInterval(pollResults, 2000);
        return () => clearInterval(interval);
    }, [currentScanId, isScanning]);

    const startScan = async () => {
        if (!url) {
            alert('Please enter a URL');
            return;
        }

        setIsScanning(true);
        setResults(null);
        setError(null);

        try {
            const response = await axios.post(`${API_URL}/scan`, {
                url: url,
                crawl_depth: crawlDepth
            });

            setCurrentScanId(response.data.scan_id);
        } catch (err) {
            setError('Error starting scan: ' + err.message);
            setIsScanning(false);
        }
    };

    const downloadReport = () => {
        if (!results) return;

        let report = `WEB VULNERABILITY SCAN REPORT\n${'='.repeat(60)}\n\nTarget URL: ${results.url}\nScan Time: ${new Date(results.timestamp).toLocaleString()}\nPages Scanned: ${results.pages_scanned ? results.pages_scanned.length : 0}\n\nSUMMARY\n${'='.repeat(60)}\nCritical: ${results.stats?.critical || 0}\nHigh: ${results.stats?.high || 0}\nMedium: ${results.stats?.medium || 0}\nLow: ${results.stats?.low || 0}\nInfo: ${results.stats?.info || 0}\n\nFINDINGS\n${'='.repeat(60)}\n\n`;

        results.findings?.forEach((finding, i) => {
            report += `${i + 1}. ${finding.title} [${(finding.severity || 'unknown').toUpperCase()}]\n   ${finding.description}\n`;
            if (finding.cve) {
                report += `   Reference: ${finding.cve} - ${finding.cve_url || ''}\n`;
            }
            report += '\n';
        });

        const blob = new Blob([report], { type: 'text/plain' });
        const downloadUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = `vulnerability-scan-${Date.now()}.txt`;
        a.click();
        URL.revokeObjectURL(downloadUrl);
    };

    const downloadJSON = () => {
        if (!results) return;

        const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
        const downloadUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = `vulnerability-scan-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(downloadUrl);
    };

    return (
        <div className="App">
            <div className="container">
                <header className="header">
                    <div className="header-content">
                        <div className="title-section">
                            <h1>Web Vulnerability Scanner</h1>
                            <button className="help-btn" onClick={() => setShowHelp(true)}>?</button>
                        </div>
                        <p className="subtitle">Security testing and vulnerability assessment tool</p>
                    </div>
                    <div className="status-section">
                        <div className="status-box">
                            {isConnected ? 'Scanner Ready' : 'Scanner Offline'}
                        </div>
                    </div>
                </header>

                {showHelp && (
                    <div className="help-overlay" onClick={() => setShowHelp(false)}>
                        <div className="help-box" onClick={(e) => e.stopPropagation()}>
                            <h2>Scanner Guide</h2>

                            <div className="help-item">
                                <h3>What does this tool do?</h3>
                                <p>This scanner checks websites for common security problems. It looks for things like missing encryption, weak settings, and exposed files that shouldn't be public.</p>
                            </div>

                            <div className="help-item">
                                <h3>How to use it</h3>
                                <p>Enter any website URL in the box and click Scan. The tool will check the site and show you what it finds. You can scan your own sites to find problems before hackers do.</p>
                            </div>

                            <div className="help-item">
                                <h3>Understanding the results</h3>
                                <p>Critical issues need immediate attention. High priority should be fixed soon. Medium and Low are less urgent but still important. Info items are just notifications.</p>
                            </div>

                            <div className="help-item">
                                <h3>What it checks</h3>
                                <p>The scanner looks for HTTPS encryption, security headers that protect against attacks, exposed admin pages, and proper cookie settings. It also crawls through pages to find more issues.</p>
                            </div>

                            <div className="help-item">
                                <h3>Reports and logs</h3>
                                <p>You can download results as text or JSON files. Everything scanned gets saved to a log file in the backend folder so you can review it later.</p>
                            </div>

                            <button className="back-btn" onClick={() => setShowHelp(false)}>
                                Back to Scanner
                            </button>
                        </div>
                    </div>
                )}

                {error && (
                    <div className="error-box">
                        <strong>Error</strong>
                        <p>{error}</p>
                    </div>
                )}

                <div className="scan-section">
                    <div className="input-area">
                        <label className="input-label">Target URL</label>
                        <div className="input-row">
                            <input
                                type="text"
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                placeholder="Enter website URL"
                                disabled={isScanning}
                                className="url-input"
                            />
                            <button
                                onClick={startScan}
                                disabled={isScanning || !isConnected}
                                className="scan-btn"
                            >
                                {isScanning ? 'Scanning...' : 'Start Scan'}
                            </button>
                        </div>
                    </div>

                    <div className="options-row">
                        <label className="option-label">
                            <span>Pages to crawl:</span>
                            <input
                                type="number"
                                min="0"
                                max="10"
                                value={crawlDepth}
                                onChange={(e) => setCrawlDepth(parseInt(e.target.value))}
                                disabled={isScanning}
                                className="number-input"
                            />
                        </label>
                    </div>
                </div>

                {isScanning && (
                    <div className="loading-box">
                        <div className="loading-bar"></div>
                        <p>Analyzing website security...</p>
                    </div>
                )}

                {results && results.findings && (
                    <div className="results-section">
                        <div className="stats-row">
                            <div className="stat-item critical-stat">
                                <div className="stat-num">{results.stats?.critical || 0}</div>
                                <div className="stat-lbl">Critical</div>
                            </div>
                            <div className="stat-item high-stat">
                                <div className="stat-num">{results.stats?.high || 0}</div>
                                <div className="stat-lbl">High</div>
                            </div>
                            <div className="stat-item medium-stat">
                                <div className="stat-num">{results.stats?.medium || 0}</div>
                                <div className="stat-lbl">Medium</div>
                            </div>
                            <div className="stat-item low-stat">
                                <div className="stat-num">{results.stats?.low || 0}</div>
                                <div className="stat-lbl">Low</div>
                            </div>
                            <div className="stat-item info-stat">
                                <div className="stat-num">{results.stats?.info || 0}</div>
                                <div className="stat-lbl">Info</div>
                            </div>
                        </div>

                        <div className="summary-box">
                            <h3>Scan Summary</h3>
                            <div className="summary-row">
                                <span>Target:</span>
                                <span>{results.url}</span>
                            </div>
                            <div className="summary-row">
                                <span>Scan Time:</span>
                                <span>{new Date(results.timestamp).toLocaleString()}</span>
                            </div>
                            {results.pages_scanned && (
                                <div className="summary-row">
                                    <span>Pages Scanned:</span>
                                    <span>{results.pages_scanned.length}</span>
                                </div>
                            )}
                        </div>

                        <div className="findings-box">
                            <h3>Security Findings</h3>
                            {results.findings.map((finding, idx) => (
                                <div key={idx} className={`finding-item ${finding.severity}`}>
                                    <div className="finding-header">
                                        <span className="finding-title">{finding.title}</span>
                                        <span className={`severity-tag ${finding.severity}`}>
                                            {finding.severity}
                                        </span>
                                    </div>
                                    <div className="finding-desc">{finding.description}</div>
                                    {finding.cve && (
                                        <a href={finding.cve_url} target="_blank" rel="noopener noreferrer" className="cve-link">
                                            {finding.cve} - View Details
                                        </a>
                                    )}
                                </div>
                            ))}
                        </div>

                        <div className="actions-row">
                            <button onClick={downloadReport} className="action-btn">
                                Download Report
                            </button>
                            <button onClick={downloadJSON} className="action-btn secondary">
                                Export JSON
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

export default App;