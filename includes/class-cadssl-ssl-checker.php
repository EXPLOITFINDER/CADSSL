<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * SSL Checker class
 * Handles all SSL/TLS related checks and functions
 */
class CADSSL_SSL_Checker {
    /**
     * Check current SSL status
     * 
     * @return array SSL status information
     */
    public function check_ssl_status() {
        $status = array(
            'is_ssl' => is_ssl(),
            'site_url_https' => strpos(site_url(), 'https://') === 0,
            'home_url_https' => strpos(home_url(), 'https://') === 0,
            'has_mixed_content' => $this->check_for_mixed_content(),
            'certificate_info' => $this->get_certificate_info()
        );
        
        return $status;
    }
    
    /**
     * Check for mixed content on homepage
     * 
     * @return bool True if mixed content is detected
     */
    public function check_for_mixed_content() {
        if (!is_ssl()) {
            return false; // Not applicable if site isn't on SSL
        }
        
        $response = wp_remote_get(home_url(), array(
            'sslverify' => true,
            'timeout' => 30
        ));
        
        if (is_wp_error($response)) {
            return false; // Can't check if request fails
        }
        
        $body = wp_remote_retrieve_body($response);
        
        // Look for common HTTP resources in HTTPS page
        $http_resources = preg_match('/http:\/\/(?!localhost|127\.0\.0\.1)([^"\')\s>]+)\.(jpg|jpeg|gif|png|js|css|svg|woff|ttf|eot|ico)/i', $body);
        
        return $http_resources > 0;
    }
    
    /**
     * Get SSL certificate information
     * 
     * @return array|false Certificate information or false if not available
     */
    public function get_certificate_info() {
        // Check if we're on HTTPS
        if (!is_ssl()) {
            return false;
        }
        
        $domain = parse_url(home_url(), PHP_URL_HOST);
        
        // Get certificate info
        $cert_info = $this->get_ssl_certificate_info($domain);
        
        if ($cert_info === false) {
            return false;
        }
        
        return $cert_info;
    }
    
    /**
     * Get SSL certificate information for a domain
     * 
     * @param string $domain Domain name
     * @return array|false Certificate information or false on error
     */
    private function get_ssl_certificate_info($domain) {
        if (!function_exists('stream_context_create') || !function_exists('stream_socket_client')) {
            return false;
        }
        
        // Create a stream context for SSL
        $context = stream_context_create(array(
            "ssl" => array(
                "capture_peer_cert" => true,
                "verify_peer" => false,
                "verify_peer_name" => false
            )
        ));
        
        // Try to connect to the domain using SSL
        $socket = @stream_socket_client("ssl://{$domain}:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
        
        if (!$socket) {
            return false;
        }
        
        // Get certificate from the context
        $params = stream_context_get_params($socket);
        if (!isset($params['options']['ssl']['peer_certificate'])) {
            fclose($socket);
            return false;
        }
        
        // Parse certificate data
        $cert_data = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
        if (empty($cert_data)) {
            fclose($socket);
            return false;
        }
        
        // Format certificate information
        $certificate_info = array(
            'subject' => isset($cert_data['subject']['CN']) ? $cert_data['subject']['CN'] : '',
            'issuer' => isset($cert_data['issuer']['O']) ? $cert_data['issuer']['O'] : '',
            'valid_from' => date('Y-m-d H:i:s', $cert_data['validFrom_time_t']),
            'expires' => date('Y-m-d H:i:s', $cert_data['validTo_time_t']),
            'days_remaining' => floor(($cert_data['validTo_time_t'] - time()) / 86400),
            'serial_number' => isset($cert_data['serialNumber']) ? $cert_data['serialNumber'] : '',
            'version' => isset($cert_data['version']) ? $cert_data['version'] : '',
            'signature_algorithm' => isset($cert_data['signatureTypeSN']) ? $cert_data['signatureTypeSN'] : '',
        );
        
        fclose($socket);
        
        return $certificate_info;
    }
    
    /**
     * Test if a URL is accessible over HTTPS
     * 
     * @param string $url URL to test
     * @return bool True if URL is accessible over HTTPS
     */
    public function test_https_url($url) {
        // Ensure URL uses HTTPS
        $https_url = str_replace('http://', 'https://', $url);
        if (strpos($https_url, 'https://') !== 0) {
            $https_url = 'https://' . $https_url;
        }
        
        $response = wp_remote_get($https_url, array(
            'sslverify' => true,
            'timeout' => 30,
            'redirection' => 0 // Don't follow redirects
        ));
        
        if (is_wp_error($response)) {
            return false;
        }
        
        $response_code = wp_remote_retrieve_response_code($response);
        
        // Consider 2xx, 3xx codes as success
        return ($response_code >= 200 && $response_code < 400);
    }
    
    /**
     * Check if server supports HTTPS
     * 
     * @return bool True if server supports HTTPS
     */
    public function server_supports_https() {
        return $this->test_https_url(home_url());
    }
    
    /**
     * Get common mixed content issues
     * 
     * @return array Array of potential mixed content issues
     */
    public function get_mixed_content_issues() {
        global $wpdb;
        
        $issues = array();
        
        // Check posts and pages for http:// content
        $posts_with_mixed_content = $wpdb->get_results(
            "SELECT ID, post_title FROM {$wpdb->posts} 
             WHERE post_status = 'publish' 
             AND (post_content LIKE '%http://%' AND post_content NOT LIKE '%http://localhost%') 
             LIMIT 50"
        );
        
        foreach ($posts_with_mixed_content as $post) {
            $issues[] = array(
                'type' => 'post',
                'id' => $post->ID,
                'title' => $post->post_title,
                'edit_url' => get_edit_post_link($post->ID, 'raw')
            );
        }
        
        // Check options that might contain URLs
        $option_keys = array(
            'siteurl', 
            'home', 
            'upload_path', 
            'upload_url_path', 
            'stylesheet_url', 
            'template_url', 
            'widget_text',
            'widget_custom_html'
        );
        
        foreach ($option_keys as $option) {
            $value = get_option($option);
            if (is_string($value) && strpos($value, 'http://') !== false) {
                $issues[] = array(
                    'type' => 'option',
                    'option' => $option,
                    'value' => $value
                );
            }
        }
        
        // Check active theme for hard-coded HTTP URLs
        $stylesheet_dir = get_stylesheet_directory();
        $template_dir = get_template_directory();
        
        $theme_files = $this->scan_directory_for_http($stylesheet_dir);
        $template_files = ($stylesheet_dir !== $template_dir) ? $this->scan_directory_for_http($template_dir) : array();
        
        $all_theme_files = array_merge($theme_files, $template_files);
        
        foreach ($all_theme_files as $file) {
            $issues[] = array(
                'type' => 'theme_file',
                'file' => $file,
                'theme' => basename(dirname($file)),
            );
        }
        
        return $issues;
    }
    
    /**
     * Scan a directory for files containing http:// URLs
     * 
     * @param string $directory Directory to scan
     * @return array Files containing http:// URLs
     */
    private function scan_directory_for_http($directory) {
        $result = array();
        
        $extensions_to_check = array('php', 'css', 'js', 'html', 'htm');
        $excluded_dirs = array('node_modules', 'vendor');
        
        if (!is_dir($directory) || !is_readable($directory)) {
            return $result;
        }
        
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
            );
            
            foreach ($it as $file) {
                // Check if we should skip this directory
                $path_parts = explode(DIRECTORY_SEPARATOR, $file->getPathname());
                $skip = false;
                foreach ($excluded_dirs as $excluded) {
                    if (in_array($excluded, $path_parts)) {
                        $skip = true;
                        break;
                    }
                }
                
                if ($skip || $file->isDir()) {
                    continue;
                }
                
                // Check file extension
                if (!in_array(strtolower($file->getExtension()), $extensions_to_check)) {
                    continue;
                }
                
                // Skip large files (> 1MB)
                if ($file->getSize() > 1048576) {
                    continue;
                }
                
                $content = @file_get_contents($file->getPathname());
                if ($content === false) {
                    continue;
                }
                
                // Look for http:// URLs that aren't localhost
                if (preg_match('/http:\/\/(?!localhost|127\.0\.0\.1)/i', $content)) {
                    $result[] = $file->getPathname();
                }
            }
        } catch (Exception $e) {
            // Handle exceptions gracefully
            error_log('CADSSL SSL Checker: Error scanning directory - ' . $e->getMessage());
        }
        
        return $result;
    }
    
    /**
     * Fix mixed content in site URLs
     */
    public function fix_site_urls() {
        $site_url = get_option('siteurl');
        $home_url = get_option('home');
        
        if (strpos($site_url, 'http://') === 0) {
            update_option('siteurl', str_replace('http://', 'https://', $site_url));
        }
        
        if (strpos($home_url, 'http://') === 0) {
            update_option('home', str_replace('http://', 'https://', $home_url));
        }
    }
    
    /**
     * Check if WordPress is properly configured for SSL
     * 
     * @return array Configuration status
     */
    public function check_wordpress_ssl_config() {
        $config = array(
            'force_ssl_admin' => defined('FORCE_SSL_ADMIN') && FORCE_SSL_ADMIN,
            'force_ssl_login' => defined('FORCE_SSL_LOGIN') && FORCE_SSL_LOGIN,
        );
        
        return $config;
    }
    
    /**
     * Check if site has valid SSL certificate
     * 
     * @return bool True if certificate is valid
     */
    public function has_valid_ssl_certificate() {
        if (!is_ssl()) {
            return false;
        }
        
        $cert_info = $this->get_certificate_info();
        if (!$cert_info) {
            return false;
        }
        
        // Check if certificate is expired
        $expires_time = strtotime($cert_info['expires']);
        $current_time = time();
        
        return $expires_time > $current_time;
    }
}
