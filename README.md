# WireGuard Android with VK TURN Proxy

This is a specialized fork of the official [WireGuard Android](https://git.zx2c4.com/wireguard-android) client with integrated support for **VK TURN Proxy**. 

It allows WireGuard traffic to be encapsulated within DTLS/TURN streams using the VK Calls infrastructure, providing a robust way to bypass network restrictions while maintaining high performance and stability.

## Key Features

- **Native Integration**: The TURN client is integrated directly into `libwg-go.so` for maximum performance and minimal battery impact.
- **VK Authentication**: Automated retrieval of TURN credentials via VK Calls anonymous tokens.
- **Sticky Stream Failover**: High reliability with multiple parallel DTLS streams and "sticky" routing to ensure WireGuard session consistency.
- **Smart DNS**: Built-in DNS bypass for restricted environments to ensure TURN connectivity even when system DNS is hijacked.
- **Seamless Configuration**: TURN settings are stored directly inside standard WireGuard `.conf` files as special metadata comments (`#@wgt:`).
- **VpnService Protection**: All proxy traffic is automatically protected from being looped back into the VPN tunnel.

## Technical Credits

This project is built upon the foundations laid by:
1. **[Official WireGuard Android](https://git.zx2c4.com/wireguard-android)** — The core VPN application and user interface.
2. **[vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy)** — The original concept and Go implementation of the VK TURN proxy.

## Building

```bash
$ git clone --recurse-submodules https://github.com/your-repo/wireguard-turn-android
$ cd wireguard-turn-android
$ ./gradlew assembleRelease
```

## Configuration

You can enable the proxy in the Tunnel Editor. The settings are appended to the Peer section of your configuration:

```ini
[Peer]
PublicKey = <key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0

# [Peer] TURN extensions
#@wgt:EnableTURN = true
#@wgt:IPPort = 1.2.3.4:56000
#@wgt:VKLink = https://vk.com/call/join/...
#@wgt:StreamNum = 4
```

For more technical details, see [info/TURN_INTEGRATION_DETAILS.md](info/TURN_INTEGRATION_DETAILS.md).

## Contributing

For UI translations, please refer to the original [WireGuard Crowdin](https://crowdin.com/project/WireGuard). For technical bugs related to the TURN integration, please open an issue in this repository.
