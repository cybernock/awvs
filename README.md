# Acunetix v25.5 Enhanced Scanner

[![Python Version](https://img.shields.io/badge/python-3.0%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Acunetix](https://img.shields.io/badge/Acunetix-v25.5-orange.svg)](https://www.acunetix.com/)

![AWVS Logo](https://www.opsmx.com/wp-content/uploads/2024/09/Acunetix-1.svg)

A powerful Python script for automating vulnerability scanning with Acunetix Web Vulnerability Scanner (AWVS) v25.5.2. This tool enables bulk target scanning, modern web vulnerability detection, and real-time monitoring.

### Core Functionality
- **Automated Target Management**: Add, configure, and scan multiple targets
- **Custom Scanning Profiles**: Create and use specialized scanning profiles
- **Batch Operations**: Process multiple targets from files
- **Configuration Management**: INI-based configuration system

### 🆕 Enhanced Features (v25.5)
- **🔍 API Discovery Scanning**: Automatic API endpoint discovery and testing
- **🌐 WebSocket Testing**: Comprehensive WebSocket security assessment
- **🔐 JWT Scanning**: JSON Web Token vulnerability detection
- **📊 GraphQL Support**: GraphQL endpoint testing and introspection
- **🛠️ Technology Detection**: Automated technology stack identification
- **🔒 Sensitive Data Scanning**: Detection of exposed sensitive information
- **⏰ Real-time Monitoring**: Critical vulnerability alerting system
- **📋 OpenAPI Specification**: Import and test OpenAPI/Swagger specifications
- **🕐 Scheduled Scanning**: Time-based scan scheduling
- **⏱️ Scan Duration Limits**: Configurable maximum scan duration

## 📋 Requirements

### System Requirements
- Python 3.0 or higher
- Acunetix Web Vulnerability Scanner (v25.5 recommended)
- Network access to Acunetix instance

### Python Dependencies
```bash
pip install requests configparser
```

## 🛠️ Installation

1. **Clone the repository:**
```bash
git clone https://github.com/cybernock/awvs.git
cd awvs
```

## ⚙️ Configuration

Edit `config.ini` file in the project root directory:

```ini
[acunetix]
awvs_url = https://your-acunetix-instance.com
api_key = your_api_key_here
default_profile_id = 11111111-1111-1111-1111-111111111111

[scan_setting]
# Enhanced Features
enable_api_discovery = true
enable_web_socket = true
enable_jwt_scan = true
enable_graphql = true
tech_detection = true
sensitive_data_scan = true
max_scan_duration = 1440

# Notification Settings
enable_wechat = false
wechat_webhook = your_wechat_webhook_url

# Scanning Options
scan_label = Production Security Scan
thread_count = 10
timeout = 30
```

### Configuration Parameters

#### Core Settings
- `awvs_url`: Your Acunetix instance URL
- `api_key`: Acunetix API key for authentication
- `default_profile_id`: Default scanning profile UUID

#### Enhanced Features
- `enable_api_discovery`: Enable automatic API endpoint discovery
- `enable_web_socket`: Enable WebSocket security testing
- `enable_jwt_scan`: Enable JWT vulnerability scanning
- `enable_graphql`: Enable GraphQL endpoint testing
- `tech_detection`: Enable technology stack detection
- `sensitive_data_scan`: Enable sensitive data exposure detection
- `max_scan_duration`: Maximum scan duration in minutes

## 🚦 Usage

### Basic Usage

Run the script:
```bash
python3 acunetix_scanner.py
```

### Menu Options

The script provides an interactive menu:

```
1. [Add Target and Start Scan]
2. [Batch Scan from File]
3. [Create Custom CVE Profile]
4. [List All Targets]
5. [Generate Scan Report]
6. [Real-time Critical Vuln Monitoring]
```

### Command Examples

#### Single Target Scan
1. Select option `1`
2. Enter target URL: `https://example.com`
3. Choose scanning profile
4. Monitor scan progress

#### Batch Scanning
1. Create a `targets.txt` file with URLs (one per line)
2. Select option `2`
3. Specify the target file path
4. All targets will be processed automatically

#### Real-time Monitoring
1. Select option `6`
2. The script will continuously monitor for critical vulnerabilities
3. Notifications will be sent via configured channels

### OpenAPI Specification Support

To use OpenAPI/Swagger specifications:

1. Place your `openapi.json` file in the project directory
2. Enable `enable_api_discovery = true` in configuration
3. Run a scan - the specification will be automatically imported

## 📊 Advanced Features

### API Discovery Scanning
- Automatically discovers API endpoints
- Tests REST API security vulnerabilities
- Supports OpenAPI/Swagger specification import
- Validates API authentication mechanisms

### WebSocket Testing
- Tests WebSocket connection security
- Validates message authentication
- Checks for injection vulnerabilities
- Tests connection hijacking scenarios

### JWT Scanning
- Validates JWT token security
- Tests for weak signing algorithms
- Checks token expiration handling
- Tests for token manipulation vulnerabilities

### GraphQL Support
- Discovers GraphQL endpoints
- Tests introspection queries
- Validates query depth limits
- Checks for information disclosure

### Real-time Monitoring
- Continuous monitoring for critical vulnerabilities
- Instant notifications via WeChat/Slack
- Automated vulnerability classification
- Real-time dashboard updates

## 📈 Monitoring and Notifications

### WeChat Integration
Configure WeChat notifications for critical vulnerabilities:

```ini
[scan_setting]
enable_wechat = true
wechat_webhook = https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_KEY
```

### Critical Vulnerability Alerts
The monitoring system will alert you when:
- Critical severity vulnerabilities are found
- High-risk exposures are detected
- Security misconfigurations are identified
- Sensitive data exposure is discovered

## 🔧 Customization

### Custom Scanning Profiles
Create specialized scanning profiles for different scenarios:

```python
def custom_profile():
    profile_data = {
        "name": "Custom API Security Scan",
        "custom": True,
        "checks": [
            "wvs/Crawler",
            "wvs/deepscan",
            "api/authentication",
            "api/authorization",
            "api/injection"
        ]
    }
```

### Adding New Features
The script is designed for extensibility. To add new features:

1. Add configuration options to `config.ini`
2. Implement the feature function
3. Integrate with the `enable_modern_features()` function
4. Update the main menu if needed

## 🐛 Troubleshooting

### Common Issues

**Connection Errors:**
- Verify Acunetix URL and API key
- Check network connectivity
- Ensure Acunetix service is running

**Scan Failures:**
- Check target accessibility
- Verify scanning profile permissions
- Review Acunetix logs for detailed errors

**API Discovery Issues:**
- Ensure OpenAPI file is valid JSON
- Check file permissions
- Verify API endpoint accessibility

### Debug Mode
Enable verbose logging by modifying the script:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📞 Support

For support and questions:
- Create an issue on GitHub
- Check the [Wiki](wiki) for additional documentation
- Review Acunetix official documentation

## ⚠️ Disclaimer

This tool is for authorized security testing only. Users are responsible for compliance with all applicable laws and regulations. Only use this tool on systems you own or have explicit permission to test.

## 🔄 Changelog

### v25.5 (Latest)
- Added API Discovery Scanning
- Implemented WebSocket Testing
- Added JWT Scanning capabilities
- GraphQL Support integration
- Real-time vulnerability monitoring
- OpenAPI specification support
- Enhanced technology detection
- Sensitive data scanning improvements

### Previous Versions
See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

---

**Made with ❤️ for the security community**
