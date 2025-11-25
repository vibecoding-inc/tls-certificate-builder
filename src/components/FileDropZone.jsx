import { useCallback, useState } from 'react';
import './FileDropZone.css';

function FileDropZone({ onFilesDropped }) {
  const [isDragging, setIsDragging] = useState(false);

  const handleDragEnter = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    
    // Only set dragging to false if we're leaving the drop zone itself
    if (e.currentTarget === e.target) {
      setIsDragging(false);
    }
  }, []);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      onFilesDropped(files);
    }
  }, [onFilesDropped]);

  const handleFileInput = useCallback((e) => {
    const files = Array.from(e.target.files);
    if (files.length > 0) {
      onFilesDropped(files);
    }
  }, [onFilesDropped]);

  return (
    <div
      className={`file-drop-zone ${isDragging ? 'dragging' : ''}`}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      <div className="drop-zone-content">
        <div className="drop-zone-icon">📁</div>
        <h2>Drop Certificate Files Here</h2>
        <p>
          Supports: PEM (.pem, .crt, .cer), DER (.der), PKCS#12 (.pfx, .p12), and private keys
        </p>
        <p className="or-text">or</p>
        <label className="file-input-label">
          <input
            type="file"
            multiple
            accept=".pem,.crt,.cer,.der,.pfx,.p12,.key"
            onChange={handleFileInput}
            className="file-input"
          />
          <span className="file-input-button">Browse Files</span>
        </label>
      </div>
    </div>
  );
}

export default FileDropZone;
