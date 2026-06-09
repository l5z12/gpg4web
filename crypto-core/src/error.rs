use wasm_bindgen::JsValue;

#[derive(Debug)]
pub enum CoreError {
    Pgp(String),
    Vault(String),
    Serde(String),
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::Pgp(m) => write!(f, "PGP error: {m}"),
            CoreError::Vault(m) => write!(f, "Vault error: {m}"),
            CoreError::Serde(m) => write!(f, "Serialization error: {m}"),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<CoreError> for JsValue {
    fn from(e: CoreError) -> Self {
        JsValue::from_str(&e.to_string())
    }
}

impl From<serde_wasm_bindgen::Error> for CoreError {
    fn from(e: serde_wasm_bindgen::Error) -> Self {
        CoreError::Serde(e.to_string())
    }
}
