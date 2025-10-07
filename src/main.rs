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
    info!("Target: {}:{}", config.target.host, config.target.port);

    match cli.command {
        Commands::Test {
            test_suite, mode, ..
        } => {
            let mut target = Target::new(config.target.clone())?;
            target.connect().await?;

            // Perform machine detection if auto-detect is enabled
            if let Some(machine_config) = &config.machine {
                if machine_config.auto_detect {
                    info!("🔍 Auto-detecting target machine type...");
                    let ssh_client = target.get_ssh_client();
                    let mut detector = MachineDetector::new(ssh_client);

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
            let mut target = Target::new(config.target)?;
            target.connect().await?;

            let ssh_client = target.get_ssh_client();
            let mut detector = MachineDetector::new(ssh_client);

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
    }

    Ok(())
}
