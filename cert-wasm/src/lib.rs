use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;
use std::collections::HashMap;

// Set panic hook for better error messages in WASM
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[derive(Serialize, Deserialize, Clone)]
#[wasm_bindgen]
pub struct CertificateInfo {
    subject: String,
    issuer: String,
    #[wasm_bindgen(skip)]
    pub subject_map: HashMap<String, String>,
    #[wasm_bindgen(skip)]
    pub issuer_map: HashMap<String, String>,
    serial_number: String,
    valid_from: String,
    valid_to: String,
    subject_common_name: String,
    issuer_common_name: String,
    is_ca: bool,
    is_self_signed: bool,
}

#[wasm_bindgen]
impl CertificateInfo {
    #[wasm_bindgen(getter)]
    pub fn subject(&self) -> String {
        self.subject.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn issuer(&self) -> String {
        self.issuer.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn serial_number(&self) -> String {
        self.serial_number.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn valid_from(&self) -> String {
        self.valid_from.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn valid_to(&self) -> String {
        self.valid_to.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn subject_common_name(&self) -> String {
        self.subject_common_name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn issuer_common_name(&self) -> String {
        self.issuer_common_name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn is_ca(&self) -> bool {
        self.is_ca
    }

    #[wasm_bindgen(getter)]
    pub fn is_self_signed(&self) -> bool {
        self.is_self_signed
    }
}

#[derive(Serialize, Deserialize)]
#[wasm_bindgen]
pub struct ParsedCertificate {
    #[wasm_bindgen(skip)]
    pub info: CertificateInfo,
    pem: String,
}

#[wasm_bindgen]
impl ParsedCertificate {
    #[wasm_bindgen(getter)]
    pub fn pem(&self) -> String {
        self.pem.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn info(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.info).unwrap_or(JsValue::NULL)
    }
}

#[derive(Serialize, Deserialize)]
#[wasm_bindgen]
pub struct PrivateKey {
    pem: String,
    encrypted: bool,
}

#[wasm_bindgen]
impl PrivateKey {
    #[wasm_bindgen(getter)]
    pub fn pem(&self) -> String {
        self.pem.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn encrypted(&self) -> bool {
        self.encrypted
    }
}

#[derive(Serialize, Deserialize)]
#[wasm_bindgen]
pub struct ParseResult {
    #[wasm_bindgen(skip)]
    pub certificates: Vec<ParsedCertificate>,
    #[wasm_bindgen(skip)]
    pub private_keys: Vec<PrivateKey>,
    needs_password: bool,
    error: Option<String>,
}

#[wasm_bindgen]
impl ParseResult {
    #[wasm_bindgen(getter)]
    pub fn certificates(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.certificates).unwrap_or(JsValue::NULL)
    }

    #[wasm_bindgen(getter)]
    pub fn private_keys(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.private_keys).unwrap_or(JsValue::NULL)
    }

    #[wasm_bindgen(getter)]
    pub fn needs_password(&self) -> bool {
        self.needs_password
    }

    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }
}

/// Extract certificate info from X509 certificate
fn extract_cert_info(cert: &X509Certificate) -> CertificateInfo {
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    // Parse subject and issuer into maps
    let mut subject_map = HashMap::new();
    let mut issuer_map = HashMap::new();

    // Extract common name from subject
    let mut subject_common_name = String::from("Unknown");
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if let Ok(value_str) = attr.attr_value().as_str() {
                let oid_str = attr.attr_type().to_id_string();
                subject_map.insert(oid_str.clone(), value_str.to_string());
                
                // CN OID is 2.5.4.3
                if oid_str.ends_with("2.5.4.3") {
                    subject_common_name = value_str.to_string();
                    subject_map.insert("CN".to_string(), value_str.to_string());
                }
            }
        }
    }

    // Extract common name from issuer  
    let mut issuer_common_name = String::from("Unknown");
    for rdn in cert.issuer().iter() {
        for attr in rdn.iter() {
            if let Ok(value_str) = attr.attr_value().as_str() {
                let oid_str = attr.attr_type().to_id_string();
                issuer_map.insert(oid_str.clone(), value_str.to_string());
                
                // CN OID is 2.5.4.3
                if oid_str.ends_with("2.5.4.3") {
                    issuer_common_name = value_str.to_string();
                    issuer_map.insert("CN".to_string(), value_str.to_string());
                }
            }
        }
    }

    let serial_number = cert.serial.to_str_radix(16);
    
    let valid_from = cert.validity().not_before.to_rfc2822().unwrap_or_else(|_| "Invalid".to_string());
    let valid_to = cert.validity().not_after.to_rfc2822().unwrap_or_else(|_| "Invalid".to_string());

    // Check if it's a CA
    let is_ca = if let Ok(Some(bc_ext)) = cert.basic_constraints() {
        bc_ext.value.ca
    } else {
        false
    };

    // Check if self-signed
    let is_self_signed = subject == issuer;

    CertificateInfo {
        subject: serde_json::to_string(&subject_map).unwrap_or_default(),
        issuer: serde_json::to_string(&issuer_map).unwrap_or_default(),
        subject_map,
        issuer_map,
        serial_number,
        valid_from,
        valid_to,
        subject_common_name,
        issuer_common_name,
        is_ca,
        is_self_signed,
    }
}

/// Parse PEM format certificates and keys
fn parse_pem(data: &[u8]) -> ParseResult {
    let mut certificates = Vec::new();
    let mut private_keys = Vec::new();

    // Convert bytes to string
    let data_str = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return ParseResult {
            certificates: Vec::new(),
            private_keys: Vec::new(),
            needs_password: false,
            error: Some("Invalid UTF-8 in PEM data".to_string()),
        },
    };

    // Parse PEM blocks manually - split by BEGIN/END markers
    let lines: Vec<&str> = data_str.lines().collect();
    let mut i = 0;
    
    while i < lines.len() {
        if lines[i].starts_with("-----BEGIN ") {
            let start_line = lines[i];
            let tag = start_line
                .trim_start_matches("-----BEGIN ")
                .trim_end_matches("-----")
                .trim();
            
            // Find the matching END marker
            let mut end_idx = i + 1;
            while end_idx < lines.len() && !lines[end_idx].starts_with("-----END ") {
                end_idx += 1;
            }
            
            if end_idx < lines.len() {
                // Collect base64 content
                let base64_content: String = lines[(i+1)..end_idx]
                    .iter()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join("");
                
                // Decode base64
                if let Ok(der_bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &base64_content) {
                    if tag == "CERTIFICATE" {
                        match X509Certificate::from_der(&der_bytes) {
                            Ok((_, cert)) => {
                                let info = extract_cert_info(&cert);
                                // Reconstruct PEM string
                                let pem_str = format!(
                                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der_bytes)
                                        .chars()
                                        .collect::<Vec<_>>()
                                        .chunks(64)
                                        .map(|c| c.iter().collect::<String>())
                                        .collect::<Vec<_>>()
                                        .join("\n")
                                );
                                certificates.push(ParsedCertificate {
                                    info,
                                    pem: pem_str,
                                });
                            }
                            Err(_) => {
                                // Silently skip invalid certificates
                            }
                        }
                    } else if tag.contains("PRIVATE KEY") {
                        // Reconstruct PEM string
                        let pem_str = format!(
                            "-----BEGIN {}-----\n{}\n-----END {}-----",
                            tag,
                            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der_bytes)
                                .chars()
                                .collect::<Vec<_>>()
                                .chunks(64)
                                .map(|c| c.iter().collect::<String>())
                                .collect::<Vec<_>>()
                                .join("\n"),
                            tag
                        );
                        let encrypted = tag.contains("ENCRYPTED");
                        private_keys.push(PrivateKey {
                            pem: pem_str,
                            encrypted,
                        });
                    }
                }
                
                i = end_idx + 1;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    ParseResult {
        certificates,
        private_keys,
        needs_password: false,
        error: None,
    }
}

/// Parse DER format certificate
fn parse_der(data: &[u8]) -> ParseResult {
    let mut certificates = Vec::new();

    match X509Certificate::from_der(data) {
        Ok((_, cert)) => {
            let info = extract_cert_info(&cert);
            // Convert DER to PEM
            let pem_str = format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data)
                    .chars()
                    .collect::<Vec<_>>()
                    .chunks(64)
                    .map(|c| c.iter().collect::<String>())
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            
            certificates.push(ParsedCertificate {
                info,
                pem: pem_str,
            });

            ParseResult {
                certificates,
                private_keys: Vec::new(),
                needs_password: false,
                error: None,
            }
        }
        Err(e) => ParseResult {
            certificates: Vec::new(),
            private_keys: Vec::new(),
            needs_password: false,
            error: Some(format!("Failed to parse DER certificate: {}", e)),
        },
    }
}

/// Parse PKCS#12 format (requires password)
fn parse_pkcs12(data: &[u8], _password: &str) -> ParseResult {
    match p12::PFX::parse(data) {
        Ok(_pfx) => {
            let certificates = Vec::new();
            let private_keys = Vec::new();

            // Try to decrypt and extract contents
            // Note: The p12 crate has limited functionality
            // For now, we'll return that it needs a password or couldn't be parsed
            ParseResult {
                certificates,
                private_keys,
                needs_password: true,
                error: Some("PKCS#12 parsing not fully implemented yet".to_string()),
            }
        }
        Err(_) => ParseResult {
            certificates: Vec::new(),
            private_keys: Vec::new(),
            needs_password: false,
            error: Some("Failed to parse PKCS#12 file".to_string()),
        },
    }
}

/// Main parsing function exposed to JavaScript
#[wasm_bindgen]
pub fn parse_certificate_file(
    data: &[u8],
    filename: &str,
    password: Option<String>,
) -> ParseResult {
    let file_ext = filename
        .split('.')
        .last()
        .unwrap_or("")
        .to_lowercase();

    match file_ext.as_str() {
        "pfx" | "p12" => {
            let pwd = password.as_deref().unwrap_or("");
            parse_pkcs12(data, pwd)
        }
        "der" => parse_der(data),
        _ => {
            // Try PEM first
            let pem_result = parse_pem(data);
            if !pem_result.certificates.is_empty() || !pem_result.private_keys.is_empty() {
                pem_result
            } else {
                // Try DER as fallback
                parse_der(data)
            }
        }
    }
}

/// Build certificate chain from a list of certificates
#[wasm_bindgen]
pub fn build_certificate_chain(certs_json: JsValue) -> JsValue {
    let certs: Result<Vec<CertificateInfo>, _> = serde_wasm_bindgen::from_value(certs_json);
    
    match certs {
        Ok(certificates) => {
            let mut chains: Vec<Vec<usize>> = Vec::new();
            
            // Find leaf certificates (non-CA or self-signed)
            let leaves: Vec<usize> = certificates
                .iter()
                .enumerate()
                .filter(|(_, cert)| !cert.is_ca || cert.is_self_signed)
                .map(|(i, _)| i)
                .collect();

            // Build chain for each leaf
            for &leaf_idx in &leaves {
                let mut chain = Vec::new();
                let mut current_idx = Some(leaf_idx);
                let mut visited = std::collections::HashSet::new();

                while let Some(idx) = current_idx {
                    if visited.contains(&idx) {
                        break;
                    }
                    visited.insert(idx);
                    chain.push(idx);

                    let current = &certificates[idx];
                    if current.is_self_signed {
                        break; // Reached root
                    }

                    // Find issuer
                    current_idx = None;
                    for (i, cert) in certificates.iter().enumerate() {
                        if !visited.contains(&i)
                            && cert.subject_common_name == current.issuer_common_name
                        {
                            current_idx = Some(i);
                            break;
                        }
                    }
                }

                if !chain.is_empty() {
                    chains.push(chain);
                }
            }

            serde_wasm_bindgen::to_value(&chains).unwrap_or(JsValue::NULL)
        }
        Err(_) => JsValue::NULL,
    }
}

/// Generate nginx format certificate chain
#[wasm_bindgen]
pub fn generate_nginx_format(
    chain_indices: Vec<usize>,
    pems: Vec<String>,
    private_key_pem: Option<String>,
) -> String {
    let mut output = String::new();

    // Add certificates in order
    for idx in chain_indices {
        if let Some(pem) = pems.get(idx) {
            output.push_str(pem);
            output.push('\n');
        }
    }

    // Add private key if available
    if let Some(key_pem) = private_key_pem {
        output.push('\n');
        output.push_str(&key_pem);
    }

    output.trim().to_string()
}
