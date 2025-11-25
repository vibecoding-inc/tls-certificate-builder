import { useCallback, useMemo } from 'react';
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './CertificateFlow.css';

import CertificateNode from './CertificateNode';
import PrivateKeyNode from './PrivateKeyNode';

const nodeTypes = {
  certificate: CertificateNode,
  privateKey: PrivateKeyNode,
};

function CertificateFlow({ certificates, privateKeys, onDownloadChain }) {
  const initialNodes = useMemo(() => {
    const nodes = [];
    
    // Add certificate nodes
    certificates.forEach((cert, index) => {
      nodes.push({
        id: `cert-${index}`,
        type: 'certificate',
        position: { x: 250, y: index * 200 },
        data: { 
          certificate: cert,
          index: index,
        },
      });
    });

    // Add private key nodes
    privateKeys.forEach((key, index) => {
      nodes.push({
        id: `key-${index}`,
        type: 'privateKey',
        position: { x: 50, y: index * 200 },
        data: { 
          privateKey: key,
          index: index,
        },
      });
    });

    return nodes;
  }, [certificates, privateKeys]);

  const initialEdges = useMemo(() => {
    const edges = [];
    
    // Create edges between certificates (chain)
    for (let i = 0; i < certificates.length - 1; i++) {
      const current = certificates[i];
      const next = certificates[i + 1];
      
      // Check if next cert issued current cert
      if (current.info && next.info && 
          current.info.issuerCommonName === next.info.subjectCommonName) {
        edges.push({
          id: `e-cert-${i}-${i + 1}`,
          source: `cert-${i}`,
          target: `cert-${i + 1}`,
          label: 'issued by',
          animated: true,
          markerEnd: {
            type: MarkerType.ArrowClosed,
          },
        });
      }
    }

    return edges;
  }, [certificates]);

  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  const onConnect = useCallback(
    (params) => setEdges((eds) => [...eds, params]),
    [setEdges]
  );

  if (certificates.length === 0 && privateKeys.length === 0) {
    return (
      <div className="certificate-flow-empty">
        <p>No certificates or keys loaded. Drop files to get started.</p>
      </div>
    );
  }

  return (
    <div className="certificate-flow-container">
      <div className="certificate-flow-header">
        <h2>Certificate Chain Visualization</h2>
        {certificates.length > 0 && (
          <button className="download-button" onClick={onDownloadChain}>
            Download Nginx Format
          </button>
        )}
      </div>
      <div className="certificate-flow">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.5}
          maxZoom={1.5}
        >
          <Background />
          <Controls />
          <MiniMap />
        </ReactFlow>
      </div>
    </div>
  );
}

export default CertificateFlow;
