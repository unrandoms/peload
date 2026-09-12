//error.rs
//Typed error enum for PE loader failure modes
//Author: iss4cf0ng/ISSAC (extended by peload fork)
//GitHub: https://github.com/unrandoms/peload

use std::fmt;

/// Typed error enum covering all PE loader failure modes.
#[derive(Debug)]
pub enum LoadError {
    /// A PE section could not be mapped into the allocated memory region.
    SectionMappingFailed(String),
    /// Base relocation could not be applied to a loaded image.
    RelocationFailed(String),
    /// A DLL import could not be resolved (missing DLL or missing export).
    IatResolutionFailed(String),
    /// A TLS callback returned an error or could not be invoked.
    #[allow(dead_code)]
    TlsCallbackFailed(String),
    /// The image entry point RVA is zero or otherwise invalid.
    EntryPointInvalid,
    /// The PE headers are missing, truncated, or contain an unexpected magic value.
    InvalidPeHeader(String),
    /// Memory allocation via VirtualAlloc failed.
    AllocationFailed(String),
    /// A Windows API call failed for a reason not covered by a more specific variant.
    WindowsApiError(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::SectionMappingFailed(msg) => write!(f, "section mapping failed: {}", msg),
            LoadError::RelocationFailed(msg) => write!(f, "relocation failed: {}", msg),
            LoadError::IatResolutionFailed(msg) => write!(f, "IAT resolution failed: {}", msg),
            LoadError::TlsCallbackFailed(msg) => write!(f, "TLS callback failed: {}", msg),
            LoadError::EntryPointInvalid => write!(f, "entry point RVA is invalid or zero"),
            LoadError::InvalidPeHeader(msg) => write!(f, "invalid PE header: {}", msg),
            LoadError::AllocationFailed(msg) => write!(f, "memory allocation failed: {}", msg),
            LoadError::WindowsApiError(msg) => write!(f, "Windows API error: {}", msg),
        }
    }
}

impl std::error::Error for LoadError {}

/// Convert a legacy String error (from the original codebase) to a LoadError.
/// Used at call-site boundaries where the original code returned `Result<_, String>`.
impl From<String> for LoadError {
    fn from(s: String) -> Self {
        LoadError::WindowsApiError(s)
    }
}
