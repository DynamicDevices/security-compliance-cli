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
    runner::TestRunner,
    target::Target,
};
use std::process;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // Load configuration
    let config = Config::from_cli(&cli)?;

    info!("Security Compliance CLI v{}", env!("CARGO_PKG_VERSION"));
    info!("Target: {}:{}", config.target.host, config.target.port);

    match cli.command {
        Commands::Test {
            test_suite, mode, ..
        } => {
            let target = Target::new(config.target)?;
            let mut runner = TestRunner::new(target, config.output, mode)?;

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
    }

    Ok(())
}
