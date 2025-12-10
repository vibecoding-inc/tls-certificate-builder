# TLS Certificate Builder

A web-based TLS certificate viewer and chain builder with drag-and-drop support for multiple certificate formats. Visualize certificate chains and generate nginx-ready certificate bundles - all processed client-side in your browser.

## Features

- 🔐 **Multi-Format Support**: Handle PEM (.pem, .crt, .cer), DER (.der), and PKCS#12 (.pfx, .p12) certificates
- 🔑 **Private Key Support**: Process encrypted and unencrypted private keys
- 🔒 **Encrypted File Handling**: Automatically prompt for passwords when encountering encrypted certificates
- 📊 **Visual Chain Display**: Interactive React Flow visualization of certificate chains
- 🎯 **Smart Chain Building**: Automatically constructs certificate chains from uploaded files
- 📦 **Nginx Export**: Generate nginx-ready certificate bundles in the correct format
- 🛡️ **Client-Side Processing**: All certificate processing happens in your browser - files never leave your machine

## Getting Started

### Installation

```bash
npm install
```

### Development

```bash
npm run dev
```

Visit `http://localhost:5173` to use the application.

### Build for Production

```bash
npm run build
```

### Preview Production Build

```bash
npm run preview
```

### Run Tests

```bash
npm test
```

## Usage

1. **Drop or Upload Files**: Drag and drop certificate files onto the drop zone, or click "Browse Files" to select them
2. **Enter Passwords**: If any files are encrypted, you'll be prompted to enter the password
3. **View Visualization**: See your certificates and private keys displayed in the interactive flow diagram
4. **Download Chain**: Click "Download Nginx Format" to export a properly formatted certificate chain ready for use with nginx

## Supported Certificate Formats

- **PEM**: Text-based format (`.pem`, `.crt`, `.cer`, `.key`)
- **DER**: Binary format (`.der`)
- **PKCS#12/PFX**: Encrypted container format (`.pfx`, `.p12`)

## Technology Stack

- **React 19**: Modern React with hooks
- **Vite**: Fast build tool and dev server
- **React Flow**: Interactive node-based UI for visualizing certificate chains
- **Rust + WebAssembly**: High-performance certificate parsing and cryptographic operations compiled to WASM
- **Client-Side Only**: No server required, all processing in the browser

## Security Notes

- All certificate processing happens entirely in your browser
- No data is transmitted to any server
- Your certificates and private keys remain on your local machine
- Perfect for handling sensitive certificates securely

## Development

### Project Structure

```
src/
├── components/
│   ├── FileDropZone.jsx        # Drag-and-drop file upload
│   ├── CertificateFlow.jsx     # React Flow visualization
│   ├── CertificateNode.jsx     # Certificate node component
│   ├── PrivateKeyNode.jsx      # Private key node component
│   └── PasswordModal.jsx       # Password input dialog
├── utils/
│   └── certificateParser.js    # WASM wrapper for certificate parsing
├── App.jsx                     # Main application component
└── main.jsx                    # Application entry point

cert-parser-wasm/
└── src/
    └── lib.rs                  # Rust WASM certificate parser implementation

tests/
└── certificateParser.test.js   # Comprehensive tests for certificate parsing and chain building
```

### Building the WASM Module

The certificate parser is implemented in Rust and compiled to WebAssembly for optimal performance. The build system generates two targets:

- `pkg/` - Node.js target for testing
- `pkg-web/` - Web target for production

To rebuild the WASM module:

```bash
# Install wasm-pack if not already installed
cargo install wasm-pack

# Build both targets
cd cert-parser-wasm

# Build for Node.js (tests)
wasm-pack build --target nodejs --out-dir pkg

# Build for web (production)
wasm-pack build --target web --out-dir pkg-web

# Return to project root
cd ..

# Build the application
npm run build
```

The appropriate WASM module is automatically loaded based on the environment (Node.js for tests, browser for production).

### Running Tests

The test suite includes comprehensive tests for certificate parsing and chain reconstruction:

```bash
npm test
```

Tests verify:
- Parsing of PEM and DER formats
- ECDSA and RSA certificate support
- Certificate chain building from complete and partial chains
- Reconstruction of chains from unordered certificates
- Private key parsing
- Mixed certificate and key file handling

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
