<?php
/**
 * Certificate Monitor
 * 
 * Monitors SSL certificate expiration and sends notifications
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class CADSSL_Certificate_Monitor {
    
    /**
     * Initialize certificate monitor
     */
    public function init() {
        // Check certificate daily
        add_action('cadssl_daily_certificate_check', array($this, 'check_certificate_expiration'));
        
        // Schedule daily check if not already scheduled
        if (!wp_next_scheduled('cadssl_daily_certificate_check')) {
            wp_schedule_event(time(), 'daily', 'cadssl_daily_certificate_check');
        }
        
        // Show admin notice for expired/expiring certificates
        add_action('admin_notices', array($this, 'display_certificate_notification'));
    }
    
    /**
     * Check certificate expiration date
     */
    public function check_certificate_expiration() {
        // Skip check if not using SSL
        if (!is_ssl()) {
            return;
        }
        
        $site_url = get_site_url();
        $domain = parse_url($site_url, PHP_URL_HOST);
        
        // Check certificate
        $cert_info = $this->get_certificate_info($domain);
        
        if ($cert_info) {
            // Store certificate info
            update_option('cadssl_certificate_expiration', $cert_info);
        }
    }
    
    /**
     * Get certificate information for a domain
     * 
     * @param string $domain Domain to check
     * @return array|bool Certificate info or false on failure
     */
    public function get_certificate_info($domain) {
        // Skip if OpenSSL is not available
        if (!function_exists('openssl_x509_parse')) {
            return false;
        }
        
        try {
            $context = stream_context_create(array(
                'ssl' => array(
                    'capture_peer_cert' => true,
                    'verify_peer' => false,
                    'verify_peer_name' => false
                )
            ));
            
            // Connect to the domain using SSL
            $stream = @stream_socket_client(
                'ssl://' . $domain . ':443', 
                $errno, 
                $errstr, 
                30, 
                STREAM_CLIENT_CONNECT, 
                $context
            );
            
            if (!$stream) {
                // Connection error
                return false;
            }
            
            // Get certificate
            $params = stream_context_get_params($stream);
            if (!isset($params['options']['ssl']['peer_certificate'])) {
                return false;
            }
            
            $cert = $params['options']['ssl']['peer_certificate'];
            $cert_data = openssl_x509_parse($cert);
            
            // Close the stream
            fclose($stream);
            
            if (!$cert_data) {
                return false;
            }
            
            // Get expiration date
            $expires = $cert_data['validTo_time_t'];
            $now = time();
            $days_remaining = round(($expires - $now) / 86400);
            
            // Prepare return data
            $cert_info = array(
                'domain' => $domain,
                'issuer' => isset($cert_data['issuer']['O']) ? $cert_data['issuer']['O'] : 'Unknown',
                'common_name' => isset($cert_data['subject']['CN']) ? $cert_data['subject']['CN'] : 'Unknown',
                'expires' => date('Y-m-d H:i:s', $expires),
                'days_remaining' => $days_remaining,
                'valid' => ($days_remaining > 0),
                'last_check' => date('Y-m-d H:i:s')
            );
            
            return $cert_info;
        } catch (Exception $e) {
            // Error getting certificate
            return false;
        }
    }
    
    /**
     * Display certificate notification in admin
     */
    public function display_certificate_notification() {
        // Check if user can manage options
        if (!current_user_can('manage_options')) {
            return;
        }
        
        // Get certificate info
        $cert_info = get_option('cadssl_certificate_expiration');
        if (!$cert_info) {
            return;
        }
        
        // Check expiration date and show notice if needed
        $options = get_option('cadssl_options');
        $threshold = isset($options['cert_expiry_threshold']) ? (int)$options['cert_expiry_threshold'] : 14;
        
        // Fix for negative days (expired certificate) - show expiry message but with proper wording
        if (isset($cert_info['days_remaining']) && $cert_info['days_remaining'] <= $threshold) {
            $message = '';
            
            if ($cert_info['days_remaining'] <= 0) {
                // Certificate has already expired
                $message = sprintf(
                    __('CADSSL Security: Your SSL certificate has expired on %s. Please renew your SSL certificate immediately.', 'cadssl'),
                    $cert_info['expires']
                );
                $class = 'error';
            } else {
                // Certificate will expire soon
                $message = sprintf(
                    __('CADSSL Security: Your SSL certificate will expire in %d days on %s. Please renew your SSL certificate soon.', 'cadssl'),
                    $cert_info['days_remaining'],
                    $cert_info['expires']
                );
                $class = 'warning';
            }
            
            printf('<div class="notice notice-%s"><p>%s</p></div>', $class, $message);
        }
    }
    
    /**
     * Force refresh the certificate information
     * 
     * @return array|bool Updated certificate info or false on failure
     */
    public function refresh_certificate_info() {
        // Skip if not using SSL
        if (!is_ssl()) {
            return false;
        }
        
        $site_url = get_site_url();
        $domain = parse_url($site_url, PHP_URL_HOST);
        
        // Check certificate
        $cert_info = $this->get_certificate_info($domain);
        
        if ($cert_info) {
            // Store certificate info
            update_option('cadssl_certificate_expiration', $cert_info);
            return $cert_info;
        }
        
        return false;
    }
}
