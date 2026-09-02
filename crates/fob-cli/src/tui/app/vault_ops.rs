use anyhow::Result;

use super::App;
use fob_host::fs_util::atomic_write;

impl App {
    pub(super) fn run_vault_init(&mut self) -> Result<()> {
        use fob_core::format::DEFAULT_VAULT_SIZE;
        use fob_core::vault::VaultInitParams;
        use zeroize::Zeroize;

        let dev = self
            .state
            .devices
            .get(self.state.selected_device)
            .ok_or_else(|| anyhow::anyhow!("No device selected"))?
            .clone();

        let vault_path = dev.path.join("vault.fob");

        let mut params = VaultInitParams::new(
            self.state.wizard.main_pass.as_bytes().to_vec(),
            DEFAULT_VAULT_SIZE,
        );

        if self.state.wizard.recovery_enabled {
            let (pubkey, privkey) = fob_core::recovery::generate_recovery_keypair();
            self.state.wizard.recovery_key_display = Some(
                fob_core::recovery::encode_private_key_for_display(&privkey)?,
            );
            // privkey's X25519/ML-KEM secrets self-zeroize on drop.
            params.recovery_pubkey = Some(pubkey);
        }

        let vault_bytes = fob_core::vault::init_vault(params)?;

        atomic_write(&vault_path, &vault_bytes)?;
        crate::cli::write_web_ui(&dev.path)?;

        self.state.wizard.main_pass.zeroize();
        self.state.wizard.main_pass_confirm.zeroize();

        Ok(())
    }

    pub(super) fn run_vault_update(&mut self) -> Result<()> {
        let dev = self
            .state
            .devices
            .get(self.state.selected_device)
            .ok_or_else(|| anyhow::anyhow!("No device selected"))?
            .clone();
        crate::cli::write_web_ui(&dev.path)?;
        Ok(())
    }
}
