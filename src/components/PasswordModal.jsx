import { useState } from 'react';
import './PasswordModal.css';

function PasswordModal({ fileName, onSubmit, onCancel }) {
  const [password, setPassword] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (password) {
      onSubmit(password);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h2>🔒 Password Required</h2>
        <p>The file <strong>{fileName}</strong> is encrypted.</p>
        <p>Please enter the password to decrypt it:</p>
        
        <form onSubmit={handleSubmit}>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password"
            autoFocus
            className="password-input"
          />
          
          <div className="modal-buttons">
            <button type="button" onClick={onCancel} className="cancel-button">
              Cancel
            </button>
            <button type="submit" className="submit-button" disabled={!password}>
              Decrypt
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default PasswordModal;
