import { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import './PrivateKeyNode.css';

function PrivateKeyNode({ data }) {
  const { privateKey } = data;

  return (
    <div className="private-key-node">
      <div className="key-header">
        <div className="key-icon">🔑</div>
        <div className="key-type">Private Key</div>
      </div>
      
      <div className="key-info">
        <div className="key-field">
          <strong>Status:</strong>
          <div className="key-value">
            {privateKey.encrypted ? '🔒 Encrypted' : '🔓 Unencrypted'}
          </div>
        </div>
        
        <div className="key-field">
          <strong>Format:</strong>
          <div className="key-value">PEM</div>
        </div>
      </div>
      
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

export default memo(PrivateKeyNode);
