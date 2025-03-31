# MLSecScan

MLSecScan is an advanced web application vulnerability scanner that combines machine learning with traditional security testing techniques. It provides real-time scanning capabilities, intelligent vulnerability detection, and a modern web dashboard for monitoring scan progress and results.

## Features

-  **Intelligent Crawling**: Advanced URL discovery with smart filtering and prioritization
-  **ML-Based Detection**: Machine learning models for anomaly detection and vulnerability identification
-  **Real-Time Dashboard**: Live monitoring of scan progress, vulnerabilities, and statistics
-  **Comprehensive Testing**: 
  - SQL Injection detection
  - Cross-Site Scripting (XSS) detection
  - Custom vulnerability signature support
  - Path traversal detection
  - File inclusion vulnerabilities
- 🛡 **Security Features**:
  - Tor proxy support for anonymous scanning
  - Rate limiting and request throttling
  - SSL verification options
  - Cookie handling and session management
-  **Advanced Analytics**:
  - Vulnerability distribution visualization
  - Response time analysis
  - Error rate tracking
  - Custom signature matching
-  **Flexible Configuration**:
  - Customizable scan depth
  - Adjustable thread count
  - Configurable timeouts
  - Custom payload support

## Installation

### Prerequisites

- Python 3.8 or higher
- Tor service (optional, for anonymous scanning)
- Git

### Dependencies

```bash
pip install -r requirements.txt
```

### System Requirements

- Linux/Unix-based system (recommended)
- Minimum 4GB RAM
- 2GB free disk space

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/Otsmane-Ahmed/MLSecScan.git
cd MLSecScan
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Start Tor service (optional):
```bash
sudo service tor start
```

4. Run the scanner:
```bash
python3 xss-sqli-cursor.py --url https://example.com --depth 3 --threads 10
```

## Usage

### Basic Usage

```bash
python3 xss-sqli-cursor.py --url <target_url> [options]
```

### Command Line Options

- `--url`: Target URL to scan
- `--file`: File containing URLs to scan
- `--depth`: Maximum crawl depth (default: 2)
- `--threads`: Number of concurrent threads (default: 3)
- `--no-tor`: Disable Tor proxy
- `--verify-ssl`: Enable SSL verification
- `--output-dir`: Directory for output files
- `--max-errors`: Maximum errors per URL before skipping (default: 5)
- `--ml-model`: Path to custom ML model file
- `--no-ml`: Disable ML-based detection

### Advanced Options

- `--add-signature`: Add custom vulnerability signature
- `--list-signatures`: List all custom signatures
- `--custom-config`: Path to custom configuration file

### Examples

1. Basic scan:
```bash
python3 xss-sqli-cursor.py --url https://example.com
```

2. Deep scan with multiple threads:
```bash
python3 xss-sqli-cursor.py --url https://example.com --depth 5 --threads 20
```

3. Scan with custom ML model:
```bash
python3 xss-sqli-cursor.py --url https://example.com --ml-model custom_model.joblib
```

4. Scan multiple URLs from file:
```bash
python3 xss-sqli-cursor.py --file urls.txt --depth 3
```

## Web Dashboard

The web dashboard provides real-time monitoring of the scan progress and results. Access it at:
```
http://localhost:5000
```

Features:
- Live progress tracking
- Vulnerability statistics
- Response time analysis
- Error rate monitoring
- Interactive charts
- Export capabilities

## Configuration

### Default Configuration

The default configuration is stored in `config.json`. You can modify it to customize:
- Scan parameters
- ML model settings
- Dashboard options
- Proxy settings
- Rate limiting rules

### Custom Signatures

Add custom vulnerability signatures using:
```bash
python3 xss-sqli-cursor.py --add-signature "category" "pattern" "description"
```

## Security Considerations

- Always obtain permission before scanning websites
- Use responsibly and ethically
- Consider rate limiting and resource usage
- Follow security best practices
- Keep the tool and dependencies updated

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all contributors
- Special thanks to the open-source community
- Built with modern security practices in mind

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. 
