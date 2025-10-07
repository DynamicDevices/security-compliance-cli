/*
 * Security Compliance CLI - SSH Key Management
 * Copyright (C) 2025 Dynamic Devices Ltd
 * Licensed under GPLv3 - see LICENSE file for details
 */

use crate::communication::CommunicationChannel;
use crate::error::{Error, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct SshKeyPair {
    pub private_key: String,
    pub public_key: String,
    pub key_type: String,
    pub comment: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct SshKeyInstaller {
    pub target_user: String,
    pub test_connection: bool,
}

impl SshKeyInstaller {
    pub fn new(target_user: String, test_connection: bool) -> Self {
        Self {
            target_user,
            test_connection,
        }
    }

    /// Generate a new Ed25519 SSH key pair with optional expiration
    pub fn generate_key_pair(
        validity_hours: u32,
        comment: Option<String>,
    ) -> Result<SshKeyPair> {
        info!("Generating new Ed25519 SSH key pair (valid for {} hours)", validity_hours);

        let mut csprng = OsRng {};
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        // Extract private and public key bytes
        let private_key_bytes = signing_key.to_bytes();
        let public_key_bytes = verifying_key.to_bytes();

        // Format private key in OpenSSH format
        let private_key_b64 = general_purpose::STANDARD.encode(&private_key_bytes);
        let public_key_b64 = general_purpose::STANDARD.encode(&public_key_bytes);

        // Create comment with expiration info
        let expires_at = if validity_hours > 0 {
            Some(Utc::now() + Duration::hours(validity_hours as i64))
        } else {
            None
        };

        let comment = comment.unwrap_or_else(|| {
            format!(
                "security-compliance-cli-temp-key-{}",
                Utc::now().format("%Y%m%d-%H%M%S")
            )
        });

        let comment_with_expiry = if let Some(exp) = expires_at {
            format!("{} expires:{}", comment, exp.format("%Y-%m-%d %H:%M:%S UTC"))
        } else {
            comment.clone()
        };

        // Format public key in OpenSSH format
        let public_key = format!("ssh-ed25519 {} {}", public_key_b64, comment_with_expiry);

        // Format private key in OpenSSH format (simplified)
        let private_key = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----",
            private_key_b64
        );

        Ok(SshKeyPair {
            private_key,
            public_key,
            key_type: "ssh-ed25519".to_string(),
            comment: comment_with_expiry,
            expires_at,
        })
    }

    /// Load an existing SSH public key from file
    pub fn load_public_key_from_file<P: AsRef<Path>>(path: P) -> Result<String> {
        let path = path.as_ref();
        info!("Loading SSH public key from: {}", path.display());

        let content = fs::read_to_string(path)
            .map_err(|e| Error::Io(e))?;

        let public_key = content.trim().to_string();

        // Basic validation - check if it looks like a valid SSH public key
        if !public_key.starts_with("ssh-") {
            return Err(Error::Config(format!(
                "Invalid SSH public key format in file: {}",
                path.display()
            )));
        }

        info!("Successfully loaded SSH public key");
        Ok(public_key)
    }

    /// Save private key to file with proper permissions
    pub fn save_private_key_to_file<P: AsRef<Path>>(
        private_key: &str,
        path: P,
    ) -> Result<()> {
        let path = path.as_ref();
        info!("Saving private key to: {}", path.display());

        fs::write(path, private_key)
            .map_err(|e| Error::Io(e))?;

        // Set restrictive permissions (600) on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)
                .map_err(|e| Error::Io(e))?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)
                .map_err(|e| Error::Io(e))?;
        }

        info!("Private key saved with secure permissions");
        Ok(())
    }

    /// Install SSH public key on target device via communication channel
    pub async fn install_public_key(
        &self,
        channel: &mut dyn CommunicationChannel,
        public_key: &str,
    ) -> Result<()> {
        info!("Installing SSH public key for user: {}", self.target_user);

        // Ensure the .ssh directory exists
        let create_ssh_dir = format!("mkdir -p /home/{}/.ssh", self.target_user);
        debug!("Creating .ssh directory: {}", create_ssh_dir);
        
        let result = channel.execute_command(&create_ssh_dir).await?;
        if result.exit_code != 0 {
            warn!("Failed to create .ssh directory: {}", result.stderr);
        }

        // Set proper permissions on .ssh directory
        let chmod_ssh_dir = format!("chmod 700 /home/{}/.ssh", self.target_user);
        debug!("Setting .ssh directory permissions: {}", chmod_ssh_dir);
        
        let result = channel.execute_command(&chmod_ssh_dir).await?;
        if result.exit_code != 0 {
            warn!("Failed to set .ssh directory permissions: {}", result.stderr);
        }

        // Add the public key to authorized_keys (append to avoid overwriting)
        let authorized_keys_path = format!("/home/{}/.ssh/authorized_keys", self.target_user);
        let add_key_command = format!(
            "echo '{}' >> {}",
            public_key.trim(),
            authorized_keys_path
        );
        
        debug!("Adding public key to authorized_keys");
        let result = channel.execute_command(&add_key_command).await?;
        if result.exit_code != 0 {
            return Err(Error::Communication(format!(
                "Failed to add public key to authorized_keys: {}",
                result.stderr
            )));
        }

        // Set proper permissions on authorized_keys
        let chmod_auth_keys = format!("chmod 600 {}", authorized_keys_path);
        debug!("Setting authorized_keys permissions: {}", chmod_auth_keys);
        
        let result = channel.execute_command(&chmod_auth_keys).await?;
        if result.exit_code != 0 {
            warn!("Failed to set authorized_keys permissions: {}", result.stderr);
        }

        // Set ownership of the .ssh directory and files
        let chown_command = format!(
            "chown -R {}:{} /home/{}/.ssh",
            self.target_user, self.target_user, self.target_user
        );
        debug!("Setting ownership: {}", chown_command);
        
        let result = channel.execute_command(&chown_command).await?;
        if result.exit_code != 0 {
            warn!("Failed to set ownership: {}", result.stderr);
        }

        info!("SSH public key installed successfully");
        Ok(())
    }

    /// Test SSH connection using the installed key
    pub async fn test_ssh_connection(
        &self,
        host: &str,
        port: u16,
        private_key: &str,
    ) -> Result<()> {
        if !self.test_connection {
            debug!("SSH connection testing disabled");
            return Ok(());
        }

        info!("Testing SSH connection with installed key...");

        // Create a temporary file for the private key
        let temp_dir = tempfile::tempdir()
            .map_err(|e| Error::Io(e))?;
        let temp_key_path = temp_dir.path().join("temp_ssh_key");
        
        Self::save_private_key_to_file(private_key, &temp_key_path)?;

        // Try to connect using ssh2
        use std::net::TcpStream;
        use ssh2::Session;

        let tcp = TcpStream::connect(format!("{}:{}", host, port))
            .map_err(|e| Error::Communication(format!("TCP connection failed: {}", e)))?;

        let mut session = Session::new()
            .map_err(|e| Error::Communication(format!("SSH session creation failed: {}", e)))?;
        
        session.set_tcp_stream(tcp);
        session.handshake()
            .map_err(|e| Error::Communication(format!("SSH handshake failed: {}", e)))?;

        // Try to authenticate with the key
        session.userauth_pubkey_file(
            &self.target_user,
            None,
            &temp_key_path,
            None,
        ).map_err(|e| Error::Communication(format!("SSH key authentication failed: {}", e)))?;

        if session.authenticated() {
            info!("✅ SSH connection test successful!");
        } else {
            return Err(Error::Communication("SSH authentication failed".to_string()));
        }

        Ok(())
    }

    /// Complete workflow: generate/load key, install it, and test connection
    pub async fn install_ssh_key_workflow(
        &self,
        channel: &mut dyn CommunicationChannel,
        public_key_file: Option<&Path>,
        validity_hours: u32,
        save_private_key_path: Option<&Path>,
        host: &str,
        port: u16,
    ) -> Result<SshKeyPair> {
        let key_pair = if let Some(pub_key_file) = public_key_file {
            // Load existing public key
            let public_key = Self::load_public_key_from_file(pub_key_file)?;
            
            // We don't have the private key, so create a placeholder
            SshKeyPair {
                private_key: String::new(), // Not available when loading from file
                public_key,
                key_type: "unknown".to_string(),
                comment: format!("loaded from {}", pub_key_file.display()),
                expires_at: None,
            }
        } else {
            // Generate new key pair
            Self::generate_key_pair(validity_hours, None)?
        };

        // Install the public key
        self.install_public_key(channel, &key_pair.public_key).await?;

        // Save private key if requested and available
        if let Some(save_path) = save_private_key_path {
            if !key_pair.private_key.is_empty() {
                Self::save_private_key_to_file(&key_pair.private_key, save_path)?;
                info!("Private key saved to: {}", save_path.display());
            } else {
                warn!("Cannot save private key - not available when loading from public key file");
            }
        }

        // Test SSH connection if we have a private key
        if self.test_connection && !key_pair.private_key.is_empty() {
            if let Err(e) = self.test_ssh_connection(host, port, &key_pair.private_key).await {
                warn!("SSH connection test failed: {}", e);
                warn!("Key was installed but connection test failed - you may need to check SSH server configuration");
            }
        }

        Ok(key_pair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_pair() {
        let key_pair = SshKeyInstaller::generate_key_pair(1, Some("test-key".to_string()))
            .expect("Should generate key pair");

        assert!(!key_pair.private_key.is_empty());
        assert!(!key_pair.public_key.is_empty());
        assert!(key_pair.public_key.starts_with("ssh-ed25519"));
        assert!(key_pair.comment.contains("test-key"));
        assert!(key_pair.expires_at.is_some());
    }

    #[test]
    fn test_generate_key_pair_no_expiry() {
        let key_pair = SshKeyInstaller::generate_key_pair(0, None)
            .expect("Should generate key pair");

        assert!(key_pair.expires_at.is_none());
    }
}
