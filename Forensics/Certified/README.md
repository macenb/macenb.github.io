# Certified

A challenge from the US CyberGames Open CTF 2024

### Decription

Files:
- [certified.pcapng](./certified.pcapng)

### Solve

Looking through the pcap, you can find an HTTP packet running a script called `backdoor.php`. When you inspect this packet further, you can see a plaintext RSA key and certificate in the packet. Following those packets, you have some TLSv2 packets, which are just encrypted HTTP packets. You need an encryption key to read those, but lucky for us we have one from the `backdoor` exploit.

I pulled the text of the RSA key, threw it into a file called `key.pem`. In wireshark, you can import a private key in Edit > Preferences > Protocols > TLS by adding a key to the "RSA keys list". I did this, and it didn't display anything in the actual pcap, but if you check the log file or browse HTTP streams, you can find the flag!

Flag: `SIVUSCG{c3rtif1abl3_h4ck3rs}`