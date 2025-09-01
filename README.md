# XILLEN Password Cracker

Advanced password auditing and cracking tool built with Java for comprehensive security assessments and penetration testing.

## 🚀 Features

- **Multiple Attack Modes**: Dictionary, brute force, hybrid, rainbow table, and mask attacks
- **Hash Support**: MD5, SHA1, SHA256, SHA512, NTLM, LM, bcrypt, PBKDF2
- **Network Protocols**: SSH, FTP, HTTP authentication cracking
- **Multi-threaded Processing**: High-performance concurrent password testing
- **Rainbow Tables**: Pre-computed hash tables for fast lookups
- **Custom Wordlists**: Support for custom password dictionaries
- **Mask Attacks**: Pattern-based password generation
- **Comprehensive Reporting**: Detailed results with timing and statistics

## 🛠️ Installation

### Prerequisites
- Java 8 or higher
- Maven (for building from source)

### Build from Source
```bash
git clone https://github.com/BengaminButton/xillen-password-cracker.git
cd xillen-password-cracker
javac PasswordCracker.java
```

### Quick Start
```bash
java PasswordCracker
```

## 📋 Usage

### Basic Hash Cracking
```bash
java PasswordCracker hash 5d41402abc4b2a76b9719d911017c592
```

### SSH Password Cracking
```bash
java PasswordCracker ssh 192.168.1.1:22 admin --wordlist passwords.txt
```

### FTP Password Cracking
```bash
java PasswordCracker ftp 192.168.1.1:21 admin --wordlist passwords.txt
```

### Brute Force Attack
```bash
java PasswordCracker hash <hash> --bruteforce abcdefghijklmnopqrstuvwxyz 1 4
```

### Mask Attack
```bash
java PasswordCracker hash <hash> --mask ?l?l?d?d
```

### Advanced Options
```bash
java PasswordCracker hash <hash> --wordlist custom.txt --threads 20 --hash-type SHA256 --output results.txt
```

## 🎯 Attack Modes

### 1. Dictionary Attack
Uses predefined wordlists to test common passwords:
```bash
java PasswordCracker hash <hash> --wordlist rockyou.txt
```

### 2. Brute Force Attack
Systematically tries all possible combinations:
```bash
java PasswordCracker hash <hash> --bruteforce abcdefghijklmnopqrstuvwxyz0123456789 1 6
```

### 3. Mask Attack
Uses patterns to generate passwords:
- `?l` = lowercase letters
- `?u` = uppercase letters  
- `?d` = digits
- `?s` = special characters
- `?a` = all characters

```bash
java PasswordCracker hash <hash> --mask ?l?l?d?d?d
```

### 4. Rainbow Table Attack
Pre-computed hash tables for fast lookups:
```bash
java PasswordCracker hash <hash> --rainbow-table
```

### 5. Hybrid Attack
Combines dictionary words with mutations:
```bash
java PasswordCracker hash <hash> --wordlist base.txt --hybrid
```

## 🔧 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--wordlist <file>` | Custom wordlist file | `--wordlist passwords.txt` |
| `--bruteforce <charset> <min> <max>` | Brute force with charset | `--bruteforce abc123 1 4` |
| `--mask <pattern>` | Mask attack pattern | `--mask ?l?l?d?d` |
| `--threads <count>` | Number of threads | `--threads 20` |
| `--hash-type <type>` | Hash algorithm | `--hash-type SHA256` |
| `--output <file>` | Save results to file | `--output results.txt` |
| `--timeout <ms>` | Connection timeout | `--timeout 5000` |

## 🌐 Network Protocol Support

### SSH Cracking
```bash
java PasswordCracker ssh 192.168.1.1:22 admin --wordlist passwords.txt --threads 10
```

### FTP Cracking
```bash
java PasswordCracker ftp 192.168.1.1:21 admin --wordlist passwords.txt
```

### HTTP Authentication
```bash
java PasswordCracker http 192.168.1.1:80 admin --wordlist passwords.txt
```

## 📊 Performance Features

- **Multi-threading**: Configurable thread pool for maximum performance
- **Memory Efficient**: Stream processing for large wordlists
- **Progress Tracking**: Real-time progress indicators
- **Rate Limiting**: Prevents overwhelming target systems
- **Timeout Management**: Configurable connection timeouts

## 🛡️ Security Considerations

### Legal Notice
This tool is designed for authorized security testing only. Users must:

- Obtain proper authorization before testing
- Comply with applicable laws and regulations
- Respect system policies and terms of service
- Use results responsibly and ethically

### Best Practices
- Use appropriate thread counts to avoid DoS
- Implement rate limiting for network attacks
- Test on isolated lab environments first
- Document all testing activities

## 📈 Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                XILLEN PASSWORD CRACKER                      ║
║              Advanced Password Auditing Tool                ║
╚══════════════════════════════════════════════════════════════╝

Version: 1.0.0
Author: Xillen Security Team

[*] Starting password cracker...
[*] Target: 5d41402abc4b2a76b9719d911017c592
[*] Threads: 10
[*] Hash type: MD5

[*] Loading wordlist: passwords.txt
[+] Loaded 10000 passwords
[*] Submitted 10000 tasks
[*] Cracking in progress...
[*] Progress: 1000/10000 (10%)
[*] Progress: 2000/10000 (20%)
...

╔══════════════════════════════════════════════════════════════╗
║                        PASSWORD FOUND!                     ║
╚══════════════════════════════════════════════════════════════╝
Password: hello
Hash: 5d41402abc4b2a76b9719d911017c592
Method: Hash
Time: 2ms
Attempts: 1234

╔══════════════════════════════════════════════════════════════╗
║                        CRACK SUMMARY                       ║
╚══════════════════════════════════════════════════════════════╝
Total attempts: 10000
Successful cracks: 1
Total time: 15432ms
Average time per attempt: 1ms
Attempts per second: 648
Results saved to: crack_results.txt
```

## 🔍 Hash Types Supported

| Hash Type | Algorithm | Example |
|-----------|-----------|---------|
| MD5 | Message Digest 5 | `5d41402abc4b2a76b9719d911017c592` |
| SHA1 | Secure Hash Algorithm 1 | `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` |
| SHA256 | SHA-256 | `2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3` |
| SHA512 | SHA-512 | `9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043` |
| NTLM | Windows NTLM | `32ed87bdb5fdc5e9cba88547376818d4` |
| LM | Windows LM | `aad3b435b51404eeaad3b435b51404ee` |

## 📁 File Formats

### Wordlist Format
Plain text file with one password per line:
```
password
123456
admin
root
test
```

### Results Format
```
XILLEN PASSWORD CRACKER - RESULTS
Generated: Mon Jan 15 14:30:25 UTC 2024
==================================================
FOUND: hello -> 5d41402abc4b2a76b9719d911017c592
Method: Hash
Time: 2ms
------------------------------
SUMMARY:
Total attempts: 10000
Successful cracks: 1
```

## 🧪 Testing

### Unit Tests
```bash
javac -cp . PasswordCrackerTest.java
java -cp . PasswordCrackerTest
```

### Integration Tests
```bash
# Test hash cracking
echo -n "hello" | md5sum
java PasswordCracker hash <hash_value>

# Test network protocols (use test lab)
java PasswordCracker ssh testlab:22 testuser --wordlist test_passwords.txt
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before conducting any security assessments.

## 🔗 Related Projects

- [XILLEN OSINT Framework](../xillen-osint/) - Open source intelligence gathering
- [XILLEN Network Scanner](../xillen-network-scanner/) - Network reconnaissance
- [XILLEN Vulnerability Scanner](../xillen-vuln-scanner/) - Comprehensive vulnerability assessment
- [XILLEN Forensics Tool](../xillen-forensics/) - Digital forensics analysis
- [XILLEN Malware Analyzer](../xillen-malware-analyzer/) - Malware analysis framework
