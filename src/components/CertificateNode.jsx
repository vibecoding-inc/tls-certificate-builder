import { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import { extractCertificateInfo } from '../utils/certificateParser';
import './CertificateNode.css';

function CertificateNode({ data }) {
  const { certificate } = data;
  const info = certificate.info || extractCertificateInfo(certificate.data);

  return (
    <div className={`certificate-node ${info.isCA ? 'ca-cert' : 'end-entity'}`}>
      <Handle type="target" position={Position.Top} />
      
      <div className="cert-header">
        <div className="cert-icon">
          {info.isSelfSigned ? '🔐' : info.isCA ? '🏛️' : '📄'}
        </div>
        <div className="cert-type">
          {info.isSelfSigned ? 'Self-Signed Root' : info.isCA ? 'CA Certificate' : 'End Entity'}
        </div>
      </div>
      
      <div className="cert-info">
        <div className="cert-field">
          <strong>Subject:</strong>
          <div className="cert-value">{info.subjectCommonName}</div>
        </div>
        
        <div className="cert-field">
          <strong>Issuer:</strong>
          <div className="cert-value">{info.issuerCommonName}</div>
        </div>
        
        <div className="cert-field">
          <strong>Valid From:</strong>
          <div className="cert-value">
            {new Date(info.validFrom).toLocaleDateString()}
          </div>
        </div>
        
        <div className="cert-field">
          <strong>Valid To:</strong>
          <div className="cert-value">
            {new Date(info.validTo).toLocaleDateString()}
          </div>
        </div>
        
        <div className="cert-field">
          <strong>Serial:</strong>
          <div className="cert-value serial">{info.serialNumber}</div>
        </div>
      </div>
      
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}

export default memo(CertificateNode);
