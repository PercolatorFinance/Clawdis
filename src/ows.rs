//! OWS (Open Wallet Standard) — encrypted key storage.
//!
//! Private keys are encrypted at rest (AES-256-GCM, scrypt KDF) in
//! the OWS vault (`~/.ows/wallets/`). Keys are decrypted only during
//! signing, then wiped from memory.

use std::path::Path;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

/// Create a new OWS wallet and return its UUID.
pub fn create_wallet(name: &str) -> Result<String> {
    create_wallet_in(name, None)
}

pub fn create_wallet_in(name: &str, vault_path: Option<&Path>) -> Result<String> {
    let wallet = ows_lib::create_wallet(name, Some(12), None, vault_path)
        .context("OWS wallet creation failed")?;
    Ok(wallet.id)
}

/// Import a private key into OWS. Returns the wallet UUID.
pub fn import_private_key(name: &str, private_key: &str) -> Result<String> {
    import_private_key_in(name, private_key, None)
}

pub fn import_private_key_in(
    name: &str,
    private_key: &str,
    vault_path: Option<&Path>,
) -> Result<String> {
    let wallet =
        ows_lib::import_wallet_private_key(name, private_key, None, None, vault_path, None, None)
            .context("OWS key import failed")?;
    Ok(wallet.id)
}

/// Delete an OWS wallet.
pub fn delete_wallet(name_or_id: &str) -> Result<()> {
    ows_lib::delete_wallet(name_or_id, None).context("OWS delete failed")
}

/// Decrypt the EVM signing key from an OWS wallet.
pub fn export_private_key(name_or_id: &str) -> Result<Zeroizing<String>> {
    export_private_key_in(name_or_id, None)
}

pub fn export_private_key_in(
    name_or_id: &str,
    vault_path: Option<&Path>,
) -> Result<Zeroizing<String>> {
    let key_bytes = ows_lib::decrypt_signing_key(
        name_or_id,
        ows_core::ChainType::Evm,
        "",
        None,
        vault_path,
    )
    .context("OWS key decryption failed")?;

    let hex = format!("0x{}", hex::encode(key_bytes.expose()));
    Ok(Zeroizing::new(hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[test]
    fn import_and_export_round_trip() {
        let vault = tempfile::tempdir().unwrap();
        let id = import_private_key_in("test", TEST_KEY, Some(vault.path())).unwrap();
        let exported = export_private_key_in(&id, Some(vault.path())).unwrap();
        assert_eq!(&*exported, TEST_KEY);
    }

    #[test]
    fn create_returns_uuid() {
        let vault = tempfile::tempdir().unwrap();
        let id = create_wallet_in("test", Some(vault.path())).unwrap();
        assert_eq!(id.len(), 36);
    }

    #[test]
    fn export_nonexistent_fails() {
        let vault = tempfile::tempdir().unwrap();
        assert!(export_private_key_in("nope", Some(vault.path())).is_err());
    }
}
