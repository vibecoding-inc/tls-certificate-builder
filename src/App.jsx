import { useState } from 'react';
import './App.css';
import FileDropZone from './components/FileDropZone';
import CertificateFlow from './components/CertificateFlow';
import PasswordModal from './components/PasswordModal';
import { 
  parseCertificateFile, 
  extractCertificateInfo, 
  buildCertificateChain,
  generateNginxFormat 
} from './utils/certificateParser';

function App() {
  const [certificates, setCertificates] = useState([]);
  const [privateKeys, setPrivateKeys] = useState([]);
  const [pendingFile, setPendingFile] = useState(null);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [error, setError] = useState(null);
  const [dragCounter, setDragCounter] = useState(0);

  const processFile = async (file, password = null) => {
    try {
      setError(null);
      const result = await parseCertificateFile(file, password);
      
      if (result.needsPassword) {
        setPendingFile(file);
        setShowPasswordModal(true);
        return;
      }

      // Process certificates and extract info
      const certsWithInfo = result.certificates.map(cert => ({
        ...cert,
        info: extractCertificateInfo(cert.data),
        fileName: file.name,
      }));

      setCertificates(prev => [...prev, ...certsWithInfo]);
      setPrivateKeys(prev => [...prev, ...result.privateKeys.map(key => ({
        ...key,
        fileName: file.name,
      }))]);

      console.log(`Processed ${file.name}:`, {
        certificates: certsWithInfo.length,
        privateKeys: result.privateKeys.length,
      });
    } catch (err) {
      console.error('Error processing file:', err);
      setError(`Failed to process ${file.name}: ${err.message}`);
    }
  };

  const handleFilesDropped = async (files) => {
    for (const file of files) {
      await processFile(file);
    }
  };

  const handlePasswordSubmit = async (password) => {
    if (pendingFile) {
      await processFile(pendingFile, password);
      setPendingFile(null);
    }
    setShowPasswordModal(false);
  };

  const handlePasswordCancel = () => {
    setPendingFile(null);
    setShowPasswordModal(false);
  };

  const handleDownloadChain = () => {
    try {
      // Build the certificate chain
      const chains = buildCertificateChain(certificates);
      
      if (chains.length === 0) {
        setError('No valid certificate chain found');
        return;
      }

      // Use the first chain (or could allow user to select)
      const chain = chains[0];
      const privateKey = privateKeys[0]; // Use first private key if available

      const nginxFormat = generateNginxFormat(chain, privateKey);

      // Download the file
      const blob = new Blob([nginxFormat], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'nginx-certificate-chain.pem';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      console.log('Downloaded nginx certificate chain');
    } catch (err) {
      console.error('Error generating nginx format:', err);
      setError(`Failed to generate nginx format: ${err.message}`);
    }
  };

  const handleClearAll = () => {
    setCertificates([]);
    setPrivateKeys([]);
    setError(null);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragCounter(prev => prev + 1);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragCounter(prev => {
      const newCount = prev - 1;
      return newCount;
    });
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragCounter(0);
    
    const files = Array.from(e.dataTransfer.files);
    await handleFilesDropped(files);
  };

  return (
    <div 
      className={`app ${dragCounter > 0 ? 'dragging-over' : ''}`}
      onDragOver={handleDragOver}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      <header className="app-header">
        <h1>🔐 TLS Certificate Builder</h1>
        <p>Drag and drop certificate files to visualize and build nginx-ready certificate chains</p>
      </header>

      <main className="app-main">
        <div className="layout-container">
          <div className="left-panel">
            <CertificateFlow
              certificates={certificates}
              privateKeys={privateKeys}
              onDownloadChain={handleDownloadChain}
            />
          </div>

          <div className="right-panel">
            <FileDropZone onFilesDropped={handleFilesDropped} />

            {error && (
              <div className="error-message">
                <span className="error-icon">⚠️</span>
                {error}
                <button onClick={() => setError(null)} className="close-error">×</button>
              </div>
            )}

            {(certificates.length > 0 || privateKeys.length > 0) && (
              <div className="summary-bar">
                <div className="summary-info">
                  <span>📄 {certificates.length} Certificate(s)</span>
                  <span>🔑 {privateKeys.length} Private Key(s)</span>
                </div>
                <button onClick={handleClearAll} className="clear-button">
                  Clear All
                </button>
              </div>
            )}

            {certificates.length > 0 && (
              <div className="certificate-details">
                <h3>Certificate Details</h3>
                {certificates.map((cert, index) => (
                  <div key={index} className="cert-detail-card">
                    <div className="cert-detail-header">
                      <strong>{cert.info.subjectCommonName}</strong>
                      <span className="cert-tag">
                        {cert.info.isSelfSigned ? 'Root' : cert.info.isCA ? 'Intermediate' : 'End Entity'}
                      </span>
                    </div>
                    <div className="cert-detail-info">
                      <div><strong>File:</strong> {cert.fileName}</div>
                      <div><strong>Issuer:</strong> {cert.info.issuerCommonName}</div>
                      <div><strong>Valid:</strong> {new Date(cert.info.validFrom).toLocaleDateString()} - {new Date(cert.info.validTo).toLocaleDateString()}</div>
                      <div><strong>Serial:</strong> <code>{cert.info.serialNumber}</code></div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </main>

      {showPasswordModal && (
        <PasswordModal
          fileName={pendingFile?.name}
          onSubmit={handlePasswordSubmit}
          onCancel={handlePasswordCancel}
        />
      )}

      <footer className="app-footer">
        <p>All processing happens client-side. Your certificates never leave your browser.</p>
      </footer>
    </div>
  );
}

export default App;
