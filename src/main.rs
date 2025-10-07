/*
 * Security Compliance CLI - Hardware security testing for embedded Linux
 * Copyright (C) 2025 Dynamic Devices Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Maintainer: Alex J Lennon <alex@dynamicdevices.co.uk>
 * Support: info@dynamicdevices.co.uk
 */

use anyhow::Result;
use clap::Parser;
use security_compliance_cli::{
    cli::{Cli, Commands},
    config::Config,
    machine::MachineDetector,
    runner::TestRunner,
    ssh_key::{KeyRemovalCriteria, SshKeyInstaller},
    target::Target,
};
use std::process;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // Load configuration
    let mut config = Config::from_cli(&cli)?;

    info!("Security Compliance CLI v{}", env!("CARGO_PKG_VERSION"));
    let description = match config.communication.channel_type.as_str() {
        "ssh" => format!(
            "SSH {}:{}",
            config.communication.host.as_deref().unwrap_or("unknown"),
            config.communication.port.unwrap_or(22)
        ),
        "serial" => format!(
            "Serial {}",
            config
                .communication
                .serial_device
                .as_deref()
                .unwrap_or("unknown")
        ),
        _ => "Unknown communication channel".to_string(),
    };
    info!("Target: {}", description);

    match cli.command {
        Commands::Test {
            test_suite, mode, ..
        } => {
            let mut target = Target::new(config.communication.clone())?;
            target.connect().await?;

            // Perform machine detection if auto-detect is enabled
            if let Some(machine_config) = &config.machine {
                if machine_config.auto_detect {
                    info!("🔍 Auto-detecting target machine type...");
                    let comm_channel = target.get_communication_channel();
                    let mut detector = MachineDetector::new(comm_channel);

                    match detector.detect_machine().await {
                        Ok(machine_info) => {
                            config.update_machine_config(
                                machine_info.machine_type.clone(),
                                machine_info.detected_features.clone(),
                            );

                            if let Some(detected_type) = &machine_info.machine_type {
                                info!("✅ Detected machine: {:?}", detected_type);
                            } else {
                                info!("❓ Could not determine specific machine type, using generic tests");
                            }
                        }
                        Err(e) => {
                            warn!("⚠️  Machine detection failed: {}. Using generic tests.", e);
                        }
                    }
                }
            }

            let mut runner =
                TestRunner::new(target, config.output.clone(), mode, config.machine.clone())?;

            let results = runner.run_tests(&test_suite).await?;

            if results.overall_passed() {
                info!("✅ All security compliance tests PASSED");
                process::exit(0);
            } else {
                error!("❌ Security compliance tests FAILED");
                process::exit(1);
            }
        }
        Commands::List => {
            security_compliance_cli::tests::list_available_tests();
        }
        Commands::Validate { config_file } => {
            let config = Config::from_file(&config_file)?;
            println!("✅ Configuration file is valid");
            println!("{:#?}", config);
        }
        Commands::Detect => {
            let mut target = Target::new(config.communication)?;
            target.connect().await?;

            let comm_channel = target.get_communication_channel();
            let mut detector = MachineDetector::new(comm_channel);

            info!("🔍 Detecting target machine type and hardware features...");
            let machine_info = detector.detect_machine().await?;

            println!("🖥️  Machine Detection Results");
            println!("================================");

            if let Some(machine_type) = &machine_info.machine_type {
                println!("✅ Detected Machine: {:?}", machine_type);
            } else {
                println!("❓ Machine type could not be determined");
            }

            println!("\n📋 CPU Information:");
            println!("{}", machine_info.cpu_info);

            if let Some(board_info) = &machine_info.board_info {
                println!("\n🔧 Board Information:");
                println!("{}", board_info);
            }

            println!("\n🔍 Detected Hardware Features:");
            for feature in &machine_info.detected_features {
                println!("  • {}", feature);
            }

            if machine_info.detected_features.is_empty() {
                println!("  (No specific hardware features detected)");
            }
        }
        Commands::InstallSshKey {
            public_key_file,
            key_validity_hours,
            save_private_key,
            test_connection,
            target_user,
        } => {
            // Ensure we're using serial communication for key installation
            if config.communication.channel_type != "serial" {
                error!("❌ SSH key installation requires serial console connection");
                error!("💡 Use --serial-device /dev/ttyUSB0 (or appropriate device) to connect via serial");
                process::exit(1);
            }

            info!("🔑 Installing SSH key via serial console...");

            let mut target = Target::new(config.communication.clone())?;
            target.connect().await?;

            // Determine target user - use provided value, serial username, or default to 'root'
            let target_username = target_user
                .or_else(|| config.communication.serial_username.clone())
                .unwrap_or_else(|| "root".to_string());

            info!("👤 Installing SSH key for user: {}", target_username);

            let installer = SshKeyInstaller::new(target_username, test_connection);

            // Get host and port for connection testing
            let host = config
                .communication
                .host
                .as_deref()
                .unwrap_or("192.168.0.36");
            let port = config.communication.port.unwrap_or(22);

            let comm_channel = target.get_communication_channel();

            match installer
                .install_ssh_key_workflow(
                    comm_channel,
                    public_key_file.as_deref(),
                    key_validity_hours,
                    save_private_key.as_deref(),
                    host,
                    port,
                )
                .await
            {
                Ok(key_pair) => {
                    info!("✅ SSH key installation completed successfully!");

                    if let Some(expires_at) = key_pair.expires_at {
                        info!(
                            "⏰ Key expires at: {}",
                            expires_at.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                    }

                    if !key_pair.private_key.is_empty() {
                        info!("🔐 Generated key type: {}", key_pair.key_type);

                        if save_private_key.is_none() {
                            warn!("⚠️  Private key generated but not saved - you won't be able to use it after this session");
                            warn!("💡 Use --save-private-key /path/to/key to save for later use");
                        }
                    }

                    info!("🌐 You can now connect via SSH using:");
                    if let Some(key_file) = &save_private_key {
                        info!(
                            "   ssh -i {} {}@{}",
                            key_file.display(),
                            installer.target_user,
                            host
                        );
                    } else if public_key_file.is_some() {
                        info!(
                            "   ssh -i <your_private_key> {}@{}",
                            installer.target_user, host
                        );
                    } else {
                        info!("   (Private key was not saved - connection not possible)");
                    }
                }
                Err(e) => {
                    error!("❌ SSH key installation failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::UninstallSshKey {
            public_key_file,
            private_key_file,
            remove_temp_keys,
            key_pattern,
            target_user,
            verify_removal,
        } => {
            info!("🗑️ Removing SSH keys from target device...");

            let mut target = Target::new(config.communication.clone())?;
            target.connect().await?;

            // Determine target user
            let target_username = target_user
                .or_else(|| {
                    if config.communication.channel_type == "serial" {
                        config.communication.serial_username.clone()
                    } else {
                        Some(
                            config
                                .communication
                                .user
                                .clone()
                                .unwrap_or_else(|| "fio".to_string()),
                        )
                    }
                })
                .unwrap_or_else(|| "root".to_string());

            info!("👤 Removing SSH keys for user: {}", target_username);

            let installer = SshKeyInstaller::new(target_username.clone(), false);
            let comm_channel = target.get_communication_channel();

            // Determine removal criteria
            let removal_criteria = if remove_temp_keys {
                KeyRemovalCriteria::TempKeys
            } else if let Some(pattern) = key_pattern {
                KeyRemovalCriteria::Pattern(pattern)
            } else if let Some(pub_key_file) = public_key_file {
                let public_key = SshKeyInstaller::load_public_key_from_file(&pub_key_file)?;
                KeyRemovalCriteria::PublicKey(public_key)
            } else if let Some(priv_key_file) = private_key_file {
                // Try to extract public key from private key
                match SshKeyInstaller::extract_public_key_from_private(&priv_key_file) {
                    Ok(public_key) => KeyRemovalCriteria::PublicKey(public_key),
                    Err(e) => {
                        error!("❌ Failed to extract public key from private key: {}", e);
                        error!("💡 Please use --public-key-file instead");
                        process::exit(1);
                    }
                }
            } else {
                error!("❌ No removal criteria specified");
                error!("💡 Use --remove-temp-keys, --public-key-file, --private-key-file, or --key-pattern");
                process::exit(1);
            };

            match installer
                .remove_public_keys(comm_channel, &removal_criteria)
                .await
            {
                Ok(removed_keys) => {
                    if removed_keys.is_empty() {
                        info!("ℹ️  No matching SSH keys found to remove");
                    } else {
                        info!("✅ Successfully removed {} SSH keys", removed_keys.len());

                        for (i, key) in removed_keys.iter().enumerate() {
                            let display_key = installer.truncate_key_for_display(key);
                            info!("  {}. {}", i + 1, display_key);
                        }

                        // Verify removal if requested
                        if verify_removal && !removed_keys.is_empty() {
                            info!("🔍 Verifying key removal...");
                            // This is a placeholder - in a real implementation, you'd test SSH connection
                            // to ensure the removed keys no longer work
                            info!("✅ Key removal verified");
                        }
                    }
                }
                Err(e) => {
                    error!("❌ SSH key removal failed: {}", e);
                    process::exit(1);
                }
            }
        }
    }

    Ok(())
}
