# TLS Certificate Builder

A web-based TLS certificate viewer and chain builder with drag-and-drop support for multiple certificate formats. Visualize certificate chains and generate nginx-ready certificate bundles - all processed client-side in your browser using a Rust WASM backend.

## Features

- 🔐 **Multi-Format Support**: Handle PEM (.pem, .crt, .cer), DER (.der), and PKCS#12 (.pfx, .p12) certificates
- 🔑 **Private Key Support**: Process encrypted and unencrypted private keys
- 🔒 **Encrypted File Handling**: Automatically prompt for passwords when encountering encrypted certificates
- 📊 **Visual Chain Display**: Interactive React Flow visualization of certificate chains
- 🎯 **Smart Chain Building**: Automatically constructs certificate chains from uploaded files
- 📦 **Nginx Export**: Generate nginx-ready certificate bundles in the correct format
- 🛡️ **Client-Side Processing**: All certificate processing happens in your browser - files never leave your machine
- ⚡ **Rust WASM Backend**: Fast and secure certificate parsing using Rust compiled to WebAssembly

## Technology Stack

- **React 19**: Modern React with hooks
- **Vite**: Fast build tool and dev server with WASM support
- **React Flow**: Interactive node-based UI for visualizing certificate chains
- **Rust + WASM**: High-performance certificate parsing using x509-parser
- **wasm-pack**: Building and packaging the Rust WASM module

## Getting Started

### Prerequisites

- Node.js (v16 or later)
- Rust toolchain (for building WASM module)
  - Install from [rust lang.org](https://www.rust-lang.org/tools/install)
- wasm-pack
  - Installed automatically via npm scripts

### Installation

```bash
npm install
```

### Development

The WASM module is built automatically as part of the dev and build scripts:

```bash
npm run dev
```

Visit `http://localhost:5173` to use the application.

### Build for Production

```bash
npm run build
```

The build process will:
1. Compile the Rust WASM module (`cert-wasm`)
2. Build the React application with Vite
3. Output to the `dist/` directory

### Building WASM Module Separately

```bash
npm run build:wasm
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
- **PKCS#12/PFX**: Encrypted container format (`.pfx`, `.p12`) [Note: Partial support in WASM backend]

## Architecture

### Frontend
- React 19 with hooks for UI components
- React Flow for interactive certificate chain visualization
- Vite for fast development and optimized production builds

### Backend (WASM)
The certificate parsing logic is implemented in Rust and compiled to WebAssembly for optimal performance and security:

```
cert-wasm/
├── src/
│   └── lib.rs          # Rust implementation of certificate parsing
├── Cargo.toml          # Rust dependencies
└── target/             # Build artifacts (gitignored)

pkg/                    # Generated WASM module (gitignored)
├── cert_wasm.js        # JavaScript bindings
├── cert_wasm_bg.wasm   # Compiled WASM binary
└── cert_wasm.d.ts      # TypeScript definitions

src/utils/
├── wasmWrapper.js      # JavaScript wrapper for WASM module
└── certificateParser.js # High-level API using WASM backend
```

### Key Components
- **x509-parser**: Rust library for X.509 certificate parsing
- **wasm-bindgen**: Rust/Wasm/JavaScript interop
- **base64 encoding**: Certificate format conversion
- **PEM parsing**: Manual PEM block parsing for maximum compatibility

## Security Notes

- All certificate processing happens entirely in your browser using WebAssembly
- Rust WASM backend provides memory safety and prevents common security vulnerabilities
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
│   ├── certificateParser.js    # High-level parsing API
│   └── wasmWrapper.js          # WASM module JavaScript wrapper
├── App.jsx                     # Main application component
└── main.jsx                    # Application entry point

cert-wasm/                      # Rust WASM module
├── src/
│   └── lib.rs                  # Certificate parsing implementation
└── Cargo.toml                  # Rust dependencies
```

### Building from Source

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Build WASM module**:
   ```bash
   npm run build:wasm
   ```
   This compiles the Rust code in `cert-wasm/` to WebAssembly and outputs to `pkg/`.

3. **Start development server**:
   ```bash
   npm run dev
   ```

4. **Run tests**:
   ```bash
   npm test
   ```

### Contributing to the WASM Module

The WASM module is located in `cert-wasm/`. To make changes:

1. Edit `cert-wasm/src/lib.rs`
2. Rebuild with `npm run build:wasm`
3. Test your changes with `npm test`

Key Rust dependencies:
- `x509-parser`: X.509 certificate parsing
- `wasm-bindgen`: JavaScript interop
- `serde`: Serialization/deserialization
- `base64`: Encoding/decoding

## Known Issues

- PKCS#12 parsing is not fully implemented in the WASM backend
- Some certificate formats may require fallback to the legacy node-forge parser

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
