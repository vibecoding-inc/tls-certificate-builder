use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

// Set panic hook for better error messages in browser
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CertificateInfo {
    pub subject: HashMap<String, String>,
    pub issuer: HashMap<String, String>,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    #[serde(rename = "validTo")]
    pub valid_to: String,
    #[serde(rename = "subjectCommonName")]
    pub subject_common_name: String,
    #[serde(rename = "issuerCommonName")]
    pub issuer_common_name: String,
    #[serde(rename = "isCA")]
    pub is_ca: bool,
    #[serde(rename = "isSelfSigned")]
    pub is_self_signed: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ParsedCertificate {
    #[serde(rename = "type")]
    pub cert_type: String,
    pub pem: String,
    pub info: CertificateInfo,
}

#[derive(Serialize, Deserialize)]
pub struct ParsedPrivateKey {
    #[serde(rename = "type")]
    pub key_type: String,
    pub pem: String,
    pub encrypted: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ParseResult {
    pub certificates: Vec<ParsedCertificate>,
    #[serde(rename = "privateKeys")]
    pub private_keys: Vec<ParsedPrivateKey>,
    #[serde(rename = "needsPassword")]
    pub needs_password: bool,
}

fn extract_name_attributes(name: &X509Name) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let oid = attr.attr_type();
            let value = attr.as_str().unwrap_or("");
            
            let key = match oid.to_id_string().as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.6" => "C",
                "2.5.4.7" => "L",
                "2.5.4.8" => "ST",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                _ => continue,
            };
            attrs.insert(key.to_string(), value.to_string());
        }
    }
    attrs
}

fn der_to_pem(der_data: &[u8], label: &str) -> String {
    let encoded = BASE64.encode(der_data);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    
    // Split into 64-character lines
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    
    pem.push_str(&format!("-----END {}-----", label));
    pem
}

fn parse_certificate_from_der(der_data: &[u8]) -> Result<ParsedCertificate, String> {
    let (_, cert) = X509Certificate::from_der(der_data)
        .map_err(|e| format!("Failed to parse DER certificate: {:?}", e))?;
    
    let subject = extract_name_attributes(&cert.subject());
    let issuer = extract_name_attributes(&cert.issuer());
    
    let subject_cn = subject.get("CN").cloned().unwrap_or_else(|| "Unknown".to_string());
    let issuer_cn = issuer.get("CN").cloned().unwrap_or_else(|| "Unknown".to_string());
    
    // Check if CA
    let is_ca = match cert.basic_constraints() {
        Ok(Some(ext)) => ext.value.ca,
        _ => false,
    };
    
    // Check if self-signed (subject == issuer)
    let is_self_signed = cert.subject() == cert.issuer();
    
    let serial_number = cert.serial.to_str_radix(16);
    
    // Convert to PEM
    let pem = der_to_pem(der_data, "CERTIFICATE");
    
    // Format dates
    let valid_from = cert.validity().not_before.to_rfc2822()
        .unwrap_or_else(|_| "Invalid date".to_string());
    let valid_to = cert.validity().not_after.to_rfc2822()
        .unwrap_or_else(|_| "Invalid date".to_string());
    
    let info = CertificateInfo {
        subject,
        issuer,
        serial_number,
        valid_from,
        valid_to,
        subject_common_name: subject_cn,
        issuer_common_name: issuer_cn,
        is_ca,
        is_self_signed,
    };
    
    Ok(ParsedCertificate {
        cert_type: "certificate".to_string(),
        pem,
        info,
    })
}

#[wasm_bindgen]
pub fn parse_pem(pem_data: &str) -> Result<JsValue, JsValue> {
    let mut certificates = Vec::new();
    let mut private_keys = Vec::new();
    
    // Parse all PEM blocks using explicit crate path
    let pem_objects = ::pem::parse_many(pem_data)
        .map_err(|e| JsValue::from_str(&format!("PEM parse error: {:?}", e)))?;
    
    for pem_item in pem_objects {
        let tag = pem_item.tag();
        match tag {
            "CERTIFICATE" => {
                match parse_certificate_from_der(pem_item.contents()) {
                    Ok(cert) => certificates.push(cert),
                    Err(e) => log(&format!("Warning: Failed to parse certificate: {}", e)),
                }
            }
            "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" | "ENCRYPTED PRIVATE KEY" => {
                let is_encrypted = tag.contains("ENCRYPTED");
                let pem_str = ::pem::encode(&pem_item);
                private_keys.push(ParsedPrivateKey {
                    key_type: "privateKey".to_string(),
                    pem: pem_str,
                    encrypted: is_encrypted,
                });
            }
            _ => log(&format!("Skipping unknown PEM block: {}", tag)),
        }
    }
    
    let result = ParseResult {
        certificates,
        private_keys,
        needs_password: false,
    };
    
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

#[wasm_bindgen]
pub fn parse_der(der_data: &[u8]) -> Result<JsValue, JsValue> {
    let cert = parse_certificate_from_der(der_data)
        .map_err(|e| JsValue::from_str(&e))?;
    
    let result = ParseResult {
        certificates: vec![cert],
        private_keys: Vec::new(),
        needs_password: false,
    };
    
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

#[wasm_bindgen]
pub fn build_certificate_chain(certs_json: JsValue) -> Result<JsValue, JsValue> {
    let certs: Vec<ParsedCertificate> = serde_wasm_bindgen::from_value(certs_json)
        .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;
    
    if certs.is_empty() {
        return serde_wasm_bindgen::to_value(&Vec::<Vec<usize>>::new())
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)));
    }
    
    // Build a map of certificate indices
    let mut cert_map: HashMap<usize, &ParsedCertificate> = HashMap::new();
    for (idx, cert) in certs.iter().enumerate() {
        cert_map.insert(idx, cert);
    }
    
    // Find leaf certificates (non-CA or self-signed)
    let mut leaves = Vec::new();
    for (idx, cert) in &cert_map {
        if !cert.info.is_ca || cert.info.is_self_signed {
            leaves.push(*idx);
        }
    }
    
    // Build chains from each leaf
    let mut chains: Vec<Vec<usize>> = Vec::new();
    
    for leaf_idx in leaves {
        let mut chain = Vec::new();
        let mut current_idx = leaf_idx;
        let mut visited = std::collections::HashSet::new();
        
        loop {
            if visited.contains(&current_idx) {
                break;
            }
            
            visited.insert(current_idx);
            chain.push(current_idx);
            
            let current_cert = cert_map.get(&current_idx).unwrap();
            
            // If self-signed, we've reached the root
            if current_cert.info.is_self_signed {
                break;
            }
            
            // Find issuer
            let mut found = false;
            for (idx, cert) in &cert_map {
                if !visited.contains(idx) && 
                   cert.info.subject_common_name == current_cert.info.issuer_common_name {
                    current_idx = *idx;
                    found = true;
                    break;
                }
            }
            
            if !found {
                break; // Can't find issuer
            }
        }
        
        if !chain.is_empty() {
            chains.push(chain);
        }
    }
    
    serde_wasm_bindgen::to_value(&chains)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

#[wasm_bindgen]
pub fn generate_nginx_format(
    chain_indices: Vec<usize>,
    certs_json: JsValue,
    private_key_pem: Option<String>,
) -> Result<String, JsValue> {
    let certs: Vec<ParsedCertificate> = serde_wasm_bindgen::from_value(certs_json)
        .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;
    
    let mut output = String::new();
    
    // Add certificates in chain order
    for &idx in &chain_indices {
        if let Some(cert) = certs.get(idx) {
            output.push_str(&cert.pem);
            output.push('\n');
        }
    }
    
    // Add private key if provided
    if let Some(key_pem) = private_key_pem {
        output.push('\n');
        output.push_str(&key_pem);
    }
    
    Ok(output.trim().to_string())
}
