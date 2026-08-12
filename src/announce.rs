//! Bonjour announcement — `_multiplex-bind._tcp`, the v1 discovery path the
//! app browses with NWBrowser (no entitlement needed app-side). The CLI
//! embeds its own announcer (mdns-sd) so headless servers without avahi
//! still show up. TXT carries only public facts: never the token, never the
//! PIN. Announce failure is downgraded by the caller to QR/clipboard.

use crate::util::b64url;
use mdns_sd::{ServiceDaemon, ServiceInfo};

pub const SERVICE_TYPE: &str = "_multiplex-bind._tcp.local.";

pub struct Announcer {
    daemon: ServiceDaemon,
    fullname: String,
}

pub struct AnnounceConfig {
    pub instance: String,
    pub port: u16,
    pub spub: [u8; 32],
    pub ssh_user: String,
    pub ssh_port: u16,
    pub first_fingerprint: Option<String>,
}

impl Announcer {
    pub fn start(config: &AnnounceConfig) -> Result<Self, String> {
        let daemon = ServiceDaemon::new().map_err(|e| e.to_string())?;
        let host = format!("{}.local.", config.instance);
        let mut txt: Vec<(&str, String)> = vec![
            ("v", "1".into()),
            ("name", config.instance.clone()),
            ("spub", b64url(&config.spub)),
            ("user", config.ssh_user.clone()),
            ("sshport", config.ssh_port.to_string()),
        ];
        if let Some(fp) = &config.first_fingerprint {
            txt.push(("fp", fp.clone()));
        }
        let properties: Vec<(&str, &str)> = txt.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &config.instance,
            &host,
            "",
            config.port,
            &properties[..],
        )
        .map_err(|e| e.to_string())?
        .enable_addr_auto();
        let fullname = info.get_fullname().to_string();
        daemon.register(info).map_err(|e| e.to_string())?;
        Ok(Announcer { daemon, fullname })
    }

    pub fn stop(self) {
        // Goodbye packet then daemon teardown; best effort on both.
        let _ = self.daemon.unregister(&self.fullname);
        std::thread::sleep(std::time::Duration::from_millis(120));
        let _ = self.daemon.shutdown();
    }
}
