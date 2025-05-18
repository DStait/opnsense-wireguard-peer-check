# opnsense-wireguard-peer-check

Makes a connection to each peer using TCP/443 and confirm if it's available. If it isn't then disables the peer,
applying config at the end. 

Only tested with Mullvad. 

Example config file, need to be in same dir as executable. 
```json
{
    "FirewallUrl": "https://firewall.local",
    "ServerName": "Mullvad",
    "Key": "your_key",
    "Secret": "your_secret"
}
```