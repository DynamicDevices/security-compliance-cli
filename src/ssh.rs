use crate::{
    config::TargetConfig,
    error::{Error, Result},
    target::CommandResult,
};
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

pub struct SshClient {
    config: TargetConfig,
    session: Option<Session>,
}

impl SshClient {
    pub fn new(config: &TargetConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            session: None,
        })
    }

    pub async fn connect(&mut self) -> Result<()> {
        let tcp = TcpStream::connect(format!("{}:{}", self.config.host, self.config.port))
            .map_err(|e| Error::SshConnection(format!("TCP connection failed: {}", e)))?;

        tcp.set_read_timeout(Some(Duration::from_secs(self.config.timeout)))
            .map_err(|e| Error::SshConnection(format!("Failed to set read timeout: {}", e)))?;

        let mut sess = Session::new()
            .map_err(|e| Error::SshConnection(format!("Failed to create SSH session: {}", e)))?;

        sess.set_tcp_stream(tcp);
        sess.handshake()
            .map_err(|e| Error::SshConnection(format!("SSH handshake failed: {}", e)))?;

        // Try SSH key authentication first
        if self.try_key_authentication(&mut sess)? {
            info!("SSH key authentication successful to {}@{}:{}", 
                  self.config.user, self.config.host, self.config.port);
        } else {
            // Fall back to password authentication
            debug!("SSH key authentication failed, trying password authentication");
            sess.userauth_password(&self.config.user, &self.config.password)
                .map_err(|e| Error::SshAuth(format!("Password authentication failed: {}", e)))?;
            
            if !sess.authenticated() {
                return Err(Error::SshAuth("Both key and password authentication failed".to_string()));
            }
            info!("SSH password authentication successful to {}@{}:{}", 
                  self.config.user, self.config.host, self.config.port);
        }

        debug!("SSH connection established to {}@{}:{}", 
               self.config.user, self.config.host, self.config.port);

        self.session = Some(sess);
        Ok(())
    }

    fn try_key_authentication(&self, session: &mut Session) -> Result<bool> {
        // Try specified key path first
        if let Some(key_path) = &self.config.ssh_key_path {
            debug!("Trying SSH key authentication with specified key: {}", key_path);
            if self.try_key_file(session, key_path)? {
                return Ok(true);
            }
        }

        // Try default key locations
        let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        let default_keys = [
            format!("{}/.ssh/test_ed25519", home_dir),  // Our test key
            format!("{}/.ssh/id_ed25519", home_dir),
            format!("{}/.ssh/id_rsa", home_dir),
            format!("{}/.ssh/id_ecdsa", home_dir),
        ];

        for key_path in &default_keys {
            if Path::new(key_path).exists() {
                debug!("Trying SSH key authentication with: {}", key_path);
                if self.try_key_file(session, key_path)? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn try_key_file(&self, session: &mut Session, key_path: &str) -> Result<bool> {
        let public_key_path = format!("{}.pub", key_path);
        
        // Try public key authentication first (if public key exists)
        if Path::new(&public_key_path).exists() {
            match session.userauth_pubkey_file(&self.config.user, Some(Path::new(&public_key_path)), Path::new(key_path), None) {
                Ok(()) => {
                    if session.authenticated() {
                        debug!("SSH key authentication successful with key: {}", key_path);
                        return Ok(true);
                    }
                }
                Err(e) => {
                    debug!("SSH key authentication failed with key {}: {}", key_path, e);
                }
            }
        } else {
            // Try with just private key (let SSH figure out the public key)
            match session.userauth_pubkey_file(&self.config.user, None, Path::new(key_path), None) {
                Ok(()) => {
                    if session.authenticated() {
                        debug!("SSH key authentication successful with key: {}", key_path);
                        return Ok(true);
                    }
                }
                Err(e) => {
                    debug!("SSH key authentication failed with key {}: {}", key_path, e);
                }
            }
        }

        Ok(false)
    }

    pub async fn execute_command(&mut self, command: &str) -> Result<CommandResult> {
        self.execute_command_with_timeout(command, Duration::from_secs(60)).await
    }

    pub async fn execute_command_with_timeout(&mut self, command: &str, timeout: Duration) -> Result<CommandResult> {
        let session = self.session.as_ref()
            .ok_or_else(|| Error::SshConnection("Not connected".to_string()))?;

        let mut channel = session.channel_session()
            .map_err(|e| Error::CommandExecution(format!("Failed to create channel: {}", e)))?;

        let start_time = Instant::now();

        channel.exec(command)
            .map_err(|e| Error::CommandExecution(format!("Failed to execute command: {}", e)))?;

        let mut stdout = String::new();
        let mut stderr = String::new();

        // Read stdout
        channel.read_to_string(&mut stdout)
            .map_err(|e| Error::CommandExecution(format!("Failed to read stdout: {}", e)))?;

        // Read stderr
        channel.stderr().read_to_string(&mut stderr)
            .map_err(|e| Error::CommandExecution(format!("Failed to read stderr: {}", e)))?;

        channel.wait_close()
            .map_err(|e| Error::CommandExecution(format!("Failed to close channel: {}", e)))?;

        let exit_code = channel.exit_status()
            .map_err(|e| Error::CommandExecution(format!("Failed to get exit status: {}", e)))?;

        let duration = start_time.elapsed();

        if duration > timeout {
            warn!("Command '{}' took {:?}, which exceeds timeout of {:?}", command, duration, timeout);
        }

        debug!("Command '{}' completed in {:?} with exit code {}", command, duration, exit_code);

        Ok(CommandResult {
            stdout,
            stderr,
            exit_code,
            duration,
        })
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(session) = self.session.take() {
            session.disconnect(None, "Disconnecting", None)
                .map_err(|e| Error::SshConnection(format!("Failed to disconnect: {}", e)))?;
        }
        Ok(())
    }
}
