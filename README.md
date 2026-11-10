# VPN Manager

Manage multiple VPN profiles (OpenVPN/WireGuard), connect/disconnect, check your exit IP, and probe Netflix reachability. The tool **does not** ship or scrape "free Netflix VPN" server lists — Netflix blocks known VPN IP ranges; for reliable streaming you need a residential/streaming-capable VPN.

## Install
```bash
cd /home/darkangel/Desktop/vpn-manager
pip install -e .
# or just run: python3 vpnmanager.py --help
```

## Setup
Create `~/.config/vpnmanager/servers.json`:
```json
{
  "servers": [
    {
      "name": "nyc-ovpn",
      "protocol": "openvpn",
      "config": "/home/darkangel/vpn/nyc.ovpn",
      "country": "US",
      "city": "NYC",
      "tags": ["us"]
    },
    {
      "name": "home-wg",
      "protocol": "wireguard",
      "config": "/etc/wireguard/home.conf",
      "country": "CA",
      "city": "Toronto",
      "tags": ["home"]
    }
  ]
}
```
You can also set `VPNMANAGER_CONFIG=/path/to/servers.json`.

## Usage
```bash
vpnmanager list
vpnmanager status
vpnmanager connect nyc-ovpn --check
vpnmanager test        # try all, disconnect each
vpnmanager best        # connect to best cached streamable server
vpnmanager check
vpnmanager disconnect
```

## Notes
- Needs `openvpn` or `wireguard-tools`. For privileged operations it will try `sudo -n` or require root.
- `test` cycles through servers (sequential) because only one tunnel can be up at a time.
- The Netflix probe is heuristic. "Plausible" means no obvious proxy block/error was seen; a real account test is still needed.
- If a provider gives you a username/password file, set `"extra": {"auth_file": "/path/to/auth.txt"}` on the OpenVPN entry.
- To avoid taking the default route (split tunnel), set `"extra": {"no_default_route": true}`.
