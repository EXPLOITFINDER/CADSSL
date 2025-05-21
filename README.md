# CADSSL Wordpress Security Plugin

A comprehensive WordPress security plugin focusing on SSL enforcement, security headers, malware detection, and overall website protection.

## Features

- **SSL Enforcement**: Force HTTPS across your entire website
- **Advanced Security Headers**: Implement OWASP recommended security headers
- **Mixed Content Detection & Fixing**: Automatically detect and fix insecure content
- **Certificate Monitoring**: Get notifications before your SSL certificate expires
- **Malware & Backdoor Scanner**: Detect malicious code in your website files
- **File Permissions Scanner**: Identify and fix insecure file permissions
- **GDPR Compliance Tools**: Cookie notices, privacy policy tools, and data handling features
- **Security Dashboard**: Get a quick overview of your website's security status

## Installation

1. Download the plugin ZIP file
2. Log into your WordPress admin panel
3. Navigate to Plugins > Add New
4. Click "Upload Plugin" and select the ZIP file
5. Click "Install Now" and then "Activate"

## Configuration

After activation, you'll find a new "CADSSL Security" menu in your WordPress admin area. Here's how to configure the main features:

### Basic SSL Settings

1. Go to CADSSL Security > Settings
2. Enable "Force SSL" to ensure all pages are served over HTTPS
3. Enable "Secure Cookies" for secure authentication
4. Configure HSTS settings if needed (use with caution)

### Security Headers

1. Go to CADSSL Security > Advanced Headers
2. Enable the security headers you want to implement
3. For Content Security Policy (CSP), start with Report-Only mode
4. Use external tools like Mozilla Observatory or SecurityHeaders.com to verify your headers

### Malware & File Scanning

1. Go to CADSSL Security > Malware Scanner
2. Run a quick scan to check core files, active plugins, and themes
3. For more thorough scanning, run a full scan
4. Review and address any suspicious files detected

### File Permissions

1. Go to CADSSL Security > File Permissions
2. Run a scan to check your file permissions
3. Review and fix any insecure permissions

### GDPR Compliance

1. Go to CADSSL Security > GDPR Compliance
2. Enable GDPR features
3. Configure your cookie notice text and privacy policy settings

## Best Practices

- Run security scans weekly
- Review your security headers regularly as web standards evolve
- Keep WordPress, themes, and plugins updated
- Implement the principle of least privilege for file permissions
- Use strong passwords and consider implementing two-factor authentication

## Development

### Syntax Highlighting

The plugin uses PrismJS for syntax highlighting in the file viewer component. The code highlighter has been customized to specifically highlight suspicious PHP functions commonly found in malware.

## Support

If you encounter any issues or have questions, please:

- Check the documentation
- Contact support at support@exploitfinder.com

## License

This plugin is licensed under the GPL v2 or later.

## Changelog

### 1.0.0
- Initial release
- SSL enforcement features
- Security headers implementation
- Malware scanning capabilities
- File permissions scanner
- GDPR compliance tools
