# MLSecScan

MLSecScan is an advanced web application vulnerability scanner that combines machine learning with traditional security testing techniques. It provides real-time scanning capabilities, intelligent vulnerability detection, and a modern web dashboard for monitoring scan progress and results.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Web Dashboard](#web-dashboard)
- [Configuration](#configuration)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## Features

### Core Capabilities
- **Intelligent Crawling**
  - Advanced URL discovery
  - Smart filtering and prioritization
  - Depth-controlled crawling
  - Resource-aware scanning

- **ML-Based Detection**
  - Anomaly detection models
  - Pattern recognition
  - Adaptive learning
  - False positive reduction

- **Real-Time Dashboard**
  - Live progress monitoring
  - Interactive statistics
  - Dynamic vulnerability updates
  - Performance metrics

### Security Testing
- **Comprehensive Testing**
  - SQL Injection detection
    - Error-based detection
    - Time-based detection
    - Boolean/Union-based detection
  - Cross-Site Scripting (XSS) detection
  - Custom vulnerability signature support
  - Path traversal detection
  - File inclusion vulnerabilities

- **Security Features**
  - Tor proxy support for anonymous scanning
  - Rate limiting and request throttling
  - SSL verification options
  - Cookie handling and session management
  - Request randomization
  - User-agent rotation

### Analytics and Reporting
- **Advanced Analytics**
  - Vulnerability distribution visualization
  - Response time analysis
  - Error rate tracking
  - Custom signature matching
  - Parameter-based vulnerability grouping
  - Sorted vulnerability reporting

- **Enhanced Reporting**
  - Parameter-based vulnerability organization
  - Sorted vulnerability counts by parameter
  - Detailed vulnerability grouping
  - Interactive vulnerability charts
  - Exportable HTML reports
  - Customizable report formats

### Configuration Options
- **Flexible Configuration**
  - Customizable scan depth
  - Adjustable thread count
  - Configurable timeouts
  - Custom payload support
  - Memory usage optimization
  - Batch processing options

## Installation

### Prerequisites
- Python 3.8 or higher
- Tor service (optional, for anonymous scanning)
- Git
- pip (Python package manager)

### System Requirements
- Linux/Unix-based system (recommended)
- Minimum 4GB RAM
- 2GB free disk space
- Network connectivity

### Installation Steps

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

## Quick Start

Run a basic scan:
```bash
python3 v8.py --url https://example.com --depth 3 --threads 10
```

Access the dashboard at `http://localhost:5000` to monitor the scan progress.

## Usage

### Basic Usage
```bash
python3 v8.py --url <target_url> [options]
```

### Command Line Options

#### Essential Options
- `--url`: Target URL to scan
- `--file`: File containing URLs to scan
- `--depth`: Maximum crawl depth (default: 2)
- `--threads`: Number of concurrent threads (default: 3)

#### Security Options
- `--no-tor`: Disable Tor proxy
- `--verify-ssl`: Enable SSL verification
- `--max-errors`: Maximum errors per URL before skipping (default: 5)

#### Output Options
- `--output-dir`: Directory for output files
- `--custom-config`: Path to custom configuration file

#### ML Options
- `--ml-model`: Path to custom ML model file
- `--no-ml`: Disable ML-based detection

### Advanced Options
- `--add-signature`: Add custom vulnerability signature
- `--list-signatures`: List all custom signatures

### Usage Examples

1. Basic scan with default settings:
```bash
python3 v8.py --url https://example.com
```

2. Deep scan with multiple threads:
```bash
python3 v8.py --url https://example.com --depth 5 --threads 20
```

3. Scan with custom ML model:
```bash
python3 v8.py --url https://example.com --ml-model custom_model.joblib
```

4. Scan multiple URLs from file:
```bash
python3 v8.py --file urls.txt --depth 3
```

## Web Dashboard

The web dashboard provides real-time monitoring of the scan progress and results. Access it at:
```
http://localhost:5000
```

### Dashboard Features
- Live progress tracking
- Vulnerability statistics
- Response time analysis
- Error rate monitoring
- Interactive charts
- Export capabilities
- Parameter-based vulnerability grouping
- Sorted vulnerability counts
- Detailed vulnerability reports

### Enhanced Reporting Features

The scanner provides comprehensive reporting capabilities:

- **Parameter-Based Grouping**
  - Vulnerabilities grouped by parameters
  - Hierarchical organization
  - Quick identification of critical issues

- **Detailed Vulnerability Information**
  - Parameter name
  - Vulnerability type
  - Affected URL
  - Detailed description
  - Severity level
  - Remediation suggestions

- **Interactive Visualization**
  - Vulnerability distribution charts
  - Response time graphs
  - Error rate analysis
  - Custom chart generation

- **Export Options**
  - HTML report generation
  - Custom report formats
  - Data export capabilities
  - Report customization

## Configuration

### Default Configuration
The default configuration is stored in `config.json`. You can modify:
- Scan parameters
- ML model settings
- Dashboard options
- Proxy settings
- Rate limiting rules

### Custom Signatures
Add custom vulnerability signatures:
```bash
python3 v8.py --add-signature "category" "pattern" "description"
```

## Security Considerations

- Always obtain permission before scanning websites
- Use responsibly and ethically
- Consider rate limiting and resource usage
- Follow security best practices
- Keep the tool and dependencies updated
- Monitor system resource usage
- Implement proper error handling
- Use secure configurations

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guide
- Write clear commit messages
- Add appropriate documentation
- Include test cases
- Update the README if needed

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The developers are not responsible for any misuse or damage caused by this tool.

Developed by Otsmane Ahmed
