// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit transport-peer trust. Forwarded headers never grant trust to a
//! direct peer. Networks must be canonical and cannot cover all addresses.

use std::net::IpAddr;
use std::str::FromStr;

#[derive(Clone, Copy)]
pub struct TrustedProxy {
    network: IpAddr,
    prefix: u8,
}

impl FromStr for TrustedProxy {
    type Err = ();

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = match source.split_once('/') {
            Some((address, prefix)) => (
                address.parse::<IpAddr>().map_err(|_| ())?,
                Some(prefix.parse::<u8>().map_err(|_| ())?),
            ),
            None => (source.parse::<IpAddr>().map_err(|_| ())?, None),
        };
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(bits);
        if prefix == 0 || prefix > bits || address.is_unspecified() {
            return Err(());
        }
        let peer = Self {
            network: address,
            prefix,
        };
        if peer.masked(address) != Some(peer.numeric_network()) {
            return Err(());
        }
        Ok(peer)
    }
}

impl TrustedProxy {
    fn numeric_network(&self) -> u128 {
        match self.network {
            IpAddr::V4(address) => u128::from(u32::from(address)),
            IpAddr::V6(address) => u128::from(address),
        }
    }

    fn masked(&self, address: IpAddr) -> Option<u128> {
        match (self.network, address) {
            (IpAddr::V4(_), IpAddr::V4(address)) => Some(u128::from(
                u32::from(address) & (u32::MAX << (32 - self.prefix)),
            )),
            (IpAddr::V6(_), IpAddr::V6(address)) => {
                Some(u128::from(address) & (u128::MAX << (128 - self.prefix)))
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        self.masked(address) == Some(self.numeric_network())
    }
}
