<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Error handler for CADSSL Security
 * Handles and logs errors to prevent critical failures
 */
class CADSSL_Error_Handler {
    /**
     * Error log file
     * 
     * @var string
     */
    private $error_log_file;
    
    /**
     * Initialize error handler
     */
    public function init() {
        // Set error log file
        $this->error_log_file = CADSSL_PATH . 'logs/error.log';
        
        // Create logs directory if it doesn't exist
        $logs_dir = CADSSL_PATH . 'logs';
        if (!file_exists($logs_dir)) {
            wp_mkdir_p($logs_dir);
            
            // Protect directory with .htaccess
            $htaccess = $logs_dir . '/.htaccess';
            file_put_contents($htaccess, "Order deny,allow\nDeny from all");
        }
        
        // Set custom error handler for the plugin
        set_error_handler(array($this, 'handle_error'), E_ALL);
        
        // Register shutdown function to catch fatal errors
        register_shutdown_function(array($this, 'handle_shutdown'));
    }
    
    /**
     * Handle PHP errors
     * 
     * @param int $errno Error number
     * @param string $errstr Error message
     * @param string $errfile File where error occurred
     * @param int $errline Line where error occurred
     * @return bool Whether error was handled
     */
    public function handle_error($errno, $errstr, $errfile, $errline) {
        // Check if error is part of our plugin
        if (strpos($errfile, 'cadssl') === false) {
            return false; // Let WordPress handle it
        }
        
        $error_type = $this->get_error_type($errno);
        $error_message = "$error_type: $errstr in $errfile on line $errline";
        
        // Log error
        $this->log_error($error_message);
        
        // For severe errors, notify admin
        if ($errno == E_ERROR || $errno == E_PARSE || $errno == E_CORE_ERROR || $errno == E_COMPILE_ERROR || $errno == E_USER_ERROR) {
            $this->notify_admin($error_message);
        }
        
        return true; // Prevent default error handling
    }
    
    /**
     * Handle PHP shutdown
     * Catches fatal errors
     */
    public function handle_shutdown() {
        $error = error_get_last();
        
        if ($error !== null && in_array($error['type'], array(E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR))) {
            // Check if error is part of our plugin
            if (strpos($error['file'], 'cadssl') !== false) {
                $error_type = $this->get_error_type($error['type']);
                $error_message = "$error_type: {$error['message']} in {$error['file']} on line {$error['line']}";
                
                // Log error
                $this->log_error($error_message);
                
                // Notify admin
                $this->notify_admin($error_message);
            }
        }
    }
    
    /**
     * Get error type string from error number
     * 
     * @param int $errno Error number
     * @return string Error type
     */
    private function get_error_type($errno) {
        switch ($errno) {
            case E_ERROR:
                return 'Fatal Error';
            case E_WARNING:
                return 'Warning';
            case E_PARSE:
                return 'Parse Error';
            case E_NOTICE:
                return 'Notice';
            case E_CORE_ERROR:
                return 'Core Error';
            case E_CORE_WARNING:
                return 'Core Warning';
            case E_COMPILE_ERROR:
                return 'Compile Error';
            case E_COMPILE_WARNING:
                return 'Compile Warning';
            case E_USER_ERROR:
                return 'User Error';
            case E_USER_WARNING:
                return 'User Warning';
            case E_USER_NOTICE:
                return 'User Notice';
            case E_STRICT:
                return 'Strict Notice';
            case E_RECOVERABLE_ERROR:
                return 'Recoverable Error';
            case E_DEPRECATED:
                return 'Deprecated';
            case E_USER_DEPRECATED:
                return 'User Deprecated';
            default:
                return 'Unknown Error';
        }
    }
    
    /**
     * Log error to file
     * 
     * @param string $message Error message
     */
    private function log_error($message) {
        $timestamp = date('[Y-m-d H:i:s]');
        $log_entry = "$timestamp $message\n";
        
        // Append to log file
        file_put_contents($this->error_log_file, $log_entry, FILE_APPEND);
        
        // Also log to WordPress error log
        error_log("CADSSL: $message");
    }
    
    /**
     * Notify admin of error
     * 
     * @param string $error_message Error message
     */
    private function notify_admin($error_message) {
        // Don't send notifications too frequently to avoid flooding admin's inbox
        $last_notification = get_option('cadssl_last_error_notification');
        if ($last_notification && (time() - $last_notification) < 3600) { // 1 hour cooldown
            return;
        }
        
        // Send email notification
        $admin_email = get_option('admin_email');
        $site_url = get_site_url();
        $subject = sprintf(__('CADSSL Security Error: %s', 'cadssl'), parse_url($site_url, PHP_URL_HOST));
        
        $message = sprintf(
            __('A critical error occurred in CADSSL Security on your WordPress site %1$s:

%2$s

This may affect the plugin functionality. Please check your site and the plugin settings.

Use the CADSSL Error Recovery Tool to troubleshoot the issue.', 'cadssl'),
            $site_url,
            $error_message
        );
        
        $headers = array('Content-Type: text/plain; charset=UTF-8');
        
        wp_mail($admin_email, $subject, $message, $headers);
        update_option('cadssl_last_error_notification', time());
    }
}
