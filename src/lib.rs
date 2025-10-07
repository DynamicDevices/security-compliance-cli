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

pub mod cli;
pub mod config;
pub mod error;
pub mod runner;
pub mod target;
pub mod tests;
pub mod output;
pub mod ssh;

pub use error::{Error, Result};
