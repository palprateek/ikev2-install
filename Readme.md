# IKEv2 VPN Installer

A bash script to set up an IKEv2 VPN server using strongSwan on Ubuntu 22.04. This script automates the installation of strongSwan, generates CA and server certificates, configures EAP-MSCHAPv2 authentication, sets up firewall rules, and enables IP forwarding. It provides a user-friendly interface to input server details and manage VPN clients, making it easy to deploy a secure IKEv2 VPN server.

## Features

- Installs and configures strongSwan for IKEv2 VPN on Ubuntu 22.04.
- Supports EAP-MSCHAPv2 authentication with username/password.
- Prompts for manual input of public IP, interface, server address, and credentials.
- Generates CA certificate for client setup (displayed for manual copying).
- Menu-driven management to add, list, revoke clients, or uninstall.
- Includes robust system checks (internet, disk space, virtualization).
- Provides detailed client configuration instructions.

## Supported Systems

- **Ubuntu 22.04** (LTS)

The script checks for Ubuntu 22.04 and ensures the system is not running on unsupported virtualization platforms (e.g., OpenVZ, LXC).

## Installation

1. Download the script:
   ```bash
   wget https://raw.githubusercontent.com/<your-username>/<your-repo>/main/ikev2-install.sh
   ```

2. Make it executable:
   ```bash
   chmod +x ikev2-install.sh
   ```

3. Run the script as root:
   ```bash
   sudo ./ikev2-install.sh
   ```

4. Follow the prompts to provide:
   - IPv4 public address (e.g., `203.0.113.1`).
   - Public interface (e.g., `eth0`).
   - VPN server address (IP or DNS, e.g., `vpn.example.com`).
   - VPN username (e.g., `vpnuser`).
   - VPN password (e.g., `securepassword123`).
   - Client name (e.g., `client1`).

5. Note for cloud providers (e.g., AWS, GCP):
   - Ensure source/destination checks are disabled in your network settings.

## Usage

After running the script, it:
- Installs strongSwan and dependencies.
- Configures the VPN server with EAP-MSCHAPv2.
- Displays the CA certificate (`/etc/ipsec.d/cacerts/ca-cert.pem`) for manual swapping.
- Saves client instructions to `/root/ikev2-clients/<client-name>-instructions.txt`.

To manage the VPN, rerun the script:
```bash
sudo ./ikev2-install.sh
```

### Management Options

- **Add a new client**: Creates a new username/password pair and instructions.
- **List all clients**: Shows all configured usernames.
- **Revoke existing client**: Removes a user’s credentials.
- **Uninstall IKEv2 VPN**: Purges strongSwan and configurations.
- **Exit**: Closes the script.

## Client Configuration

The script outputs the CA certificate (`cat /etc/ipsec.d/cacerts/ca-cert.pem`) during setup. Copy this to a file named `ca-cert.pem` on your client device. Alternatively, use SCP to transfer it:
```bash
scp root@<server-address>:/etc/ipsec.d/cacerts/ca-cert.pem .
```

Follow the instructions in `/root/ikev2-clients/<client-name>-instructions.txt` for client setup. Below are the complete steps to configure clients on Windows, macOS, and Android.

### Configuring an IKEv2 Client on Windows

To configure your Windows client, you will need to copy the CA certificate from your server to your client machine. On your server, output the contents of the CA certificate by running the following command:

```bash
cat /etc/ipsec.d/cacerts/ca-cert.pem
```

Copy the output to your client machine, including the `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` lines, and save it to a file with a `.pem` extension (for example, `ca-cert.pem`). You could also use a tool like `scp` to copy the file from your server to your client machine.

Then, follow these steps to configure the Windows client:

1. Import the CA certificate to the Windows certificate store:
   - Open the `ca-cert.pem` file in a text editor and copy the certificate text.
   - Press `Win + R`, type `mmc`, and press `Enter` to open the Microsoft Management Console.
   - Go to `File` > `Add/Remove Snap-in`, select `Certificates`, and click `Add`.
   - Choose `Computer account` and click `Next`, then `Finish`, and `OK`.
   - Expand `Certificates (Local Computer)` > `Trusted Root Certification Authorities` > `Certificates`.
   - Right-click `Certificates`, select `All Tasks` > `Import`.
   - Browse to the `ca-cert.pem` file (or paste the certificate text), and complete the import wizard.

2. Create a new VPN connection:
   - Go to `Settings` > `Network & Internet` > `VPN` > `Add a VPN connection`.
   - Set `VPN provider` to `Windows (built-in)`.
   - Enter a `Connection name` (e.g., `IKEv2 VPN`).
   - Enter the `Server name or address` (your server’s public IP or DNS name, e.g., `vpn.example.com`).
   - Set `VPN type` to `IKEv2`.
   - Set `Type of sign-in info` to `Username and password`.
   - Enter the username and password you configured in `/etc/ipsec.secrets` (e.g., `vpnuser`, `securepassword123`).
   - Save the connection.

3. Connect to the VPN:
   - Go to `Settings` > `Network & Internet` > `VPN`, select the connection, and click `Connect`.
   - Enter your username and password if prompted.

Once connected, you can verify the connection by checking your IP address or accessing a server resource. If you encounter issues, ensure the CA certificate is correctly imported and the server address is reachable.

### Configuring Clients on macOS

To configure a macOS client, you will need the CA certificate (`ca-cert.pem`) from your server. Copy it to your macOS machine using the `cat` command or `scp` as described above.

Then, follow these steps:

1. Import the CA certificate:
   - Open `Keychain Access` (use Spotlight to find it).
   - Go to `File` > `Import Items`, select the `ca-cert.pem` file, and choose the `System` keychain.
   - Enter your admin password if prompted.
   - Find the certificate in the `System` keychain, double-click it, expand the `Trust` section, and set `Secure Sockets Layer (SSL)` to `Always Trust`.

2. Create a new VPN connection:
   - Go to `System Preferences` > `Network` and click the `+` button to add a new interface.
   - Set `Interface` to `VPN`, `VPN Type` to `IKEv2`, and enter a `Service Name` (e.g., `IKEv2 VPN`).
   - Enter the `Server Address` (your server’s public IP or DNS name, e.g., `vpn.example.com`).
   - Enter the `Remote ID` (same as the server address, e.g., `vpn.example.com`).
   - Click `Authentication Settings`, select `Username`, and enter the username and password from `/etc/ipsec.secrets` (e.g., `vpnuser`, `securepassword123`).
   - Click `OK`, then `Apply`, and `Connect` to test the connection.

### Configuring Clients on Android

To configure an Android client, you will need the CA certificate (`ca-cert.pem`) from your server. Copy it to your Android device using `scp` or by transferring the file via email or another secure method.

Then, follow these steps:

1. Install the strongSwan VPN client:
   - Download the `strongSwan VPN Client` app from the Google Play Store.

2. Import the CA certificate:
   - Transfer the `ca-cert.pem` file to your Android device.
   - Open the strongSwan app, go to `CA certificates` > `Import certificate`, and select the `ca-cert.pem` file.

3. Create a new VPN profile:
   - In the strongSwan app, tap `Add VPN Profile`.
   - Enter the `Server` (your server’s public IP or DNS name, e.g., `vpn.example.com`).
   - Set `VPN Type` to `IKEv2 EAP (Username/Password)`.
   - Enter the username and password from `/etc/ipsec.secrets` (e.g., `vpnuser`, `securepassword123`).
   - Select the imported CA certificate.
   - Save the profile and tap it to connect.

If the connection fails, ensure the CA certificate is correctly imported and the server address is reachable. Check the strongSwan app logs for errors.

## Troubleshooting

- **Package installation fails**: Check `/var/log/apt/term.log` for errors.
- **StrongSwan service fails**: Run `journalctl -u strongswan-starter` for logs.
- **Firewall issues**: Verify rules with `iptables -L -v -n`.
- **Client connection errors**: Ensure the CA certificate is imported correctly and the server address resolves. Check firewall rules and server logs.

If issues persist, open an issue on the GitHub repository with relevant logs.

## Contributing

Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m 'Add your feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

Ensure your changes are tested on Ubuntu 22.04.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.