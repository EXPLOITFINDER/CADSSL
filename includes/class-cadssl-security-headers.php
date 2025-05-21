<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class CADSSL_Security_Headers {
    /**
     * Apply security headers
     */
    public function apply_security_headers() {
        add_action('send_headers', array($this, 'send_security_headers'));
    }
    
    /**
     * Send security headers
     */
    public function send_security_headers() {
        // X-Content-Type-Options
        header('X-Content-Type-Options: nosniff');
        
        // X-XSS-Protection
        header('X-XSS-Protection: 1; mode=block');
        
        // X-Frame-Options
        header('X-Frame-Options: SAMEORIGIN');
        
        // Referrer-Policy
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // Permissions-Policy (formerly Feature-Policy)
        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
        
        // Only add HSTS header on HTTPS
        if (is_ssl()) {
            header('Strict-Transport-Security: max-age=31536000');
        }
    }
}
