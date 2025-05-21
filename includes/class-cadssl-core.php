<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Main CADSSL Core class
 */
class CADSSL_Core {
    
    /**
     * Initialize plugin
     */
    public function init() {
        // Load required files
        $this->load_dependencies();
        
        // Register activation and deactivation hooks
        register_activation_hook(CADSSL_FILE, array($this, 'activate'));
        register_deactivation_hook(CADSSL_FILE, array($this, 'deactivate'));
        
        // Schedule cleanup task
        add_action('cadssl_daily_cleanup', array($this, 'cleanup_old_data'));
        if (!wp_next_scheduled('cadssl_daily_cleanup')) {
            wp_schedule_event(time(), 'daily', 'cadssl_daily_cleanup');
        }
        
        // Initialize components
        $this->initialize_components();
    }
    
    /**
     * Load dependencies
     */
    private function load_dependencies() {
        // Load classes
        $required_files = array(
            'class-cadssl-scanner-helper.php',
            'class-cadssl-scan-lock-manager.php',
            'class-cadssl-progress-tracker.php', // Add our new class
            'class-cadssl-malware-patterns.php',
            'class-cadssl-malware-scanner.php',
            'class-cadssl-background-scanner.php',
            'class-cadssl-dashboard.php',
            // [Other existing files...]
        );
        
        foreach ($required_files as $file) {
            $path = CADSSL_PATH . 'includes/' . $file;
            if (file_exists($path)) {
                require_once $path;
            }
        }
    }
    
    /**
     * Initialize components
     */
    private function initialize_components() {
        // Initialize malware scanner
        $malware_scanner = new CADSSL_Malware_Scanner();
        $malware_scanner->init();
        
        // Initialize background scanner
        $background_scanner = new CADSSL_Background_Scanner();
        $background_scanner->init();
        
        // Initialize dashboard
        $dashboard = new CADSSL_Dashboard();
        $dashboard->init();
        
        // [Other initializations...]
        
        // Clean old progress files daily
        if (class_exists('CADSSL_Progress_Tracker')) {
            add_action('cadssl_daily_cleanup', array('CADSSL_Progress_Tracker', 'clean_old_progress_files'));
        }
    }
    
    /**
     * Clean up old data
     */
    public function cleanup_old_data() {
        // Clean up progress files older than 2 days
        if (class_exists('CADSSL_Progress_Tracker')) {
            CADSSL_Progress_Tracker::clean_old_progress_files(172800); // 48 hours
        }
        
        // [Other cleanup tasks...]
    }
    
    /**
     * Check if required dependencies exist
     * 
     * @return bool True if all dependencies exist
     */
    private function check_dependencies() {
        $required_classes = array(
            'CADSSL_SSL_Checker',
            'CADSSL_Security_Headers'
        );
        
        foreach ($required_classes as $class) {
            if (!class_exists($class)) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Display dependency error notice
     */
    public function display_dependency_error() {
        ?>
        <div class="notice notice-error">
            <p><?php _e('CADSSL Security: Required components are missing. Please reinstall the plugin or contact support.', 'cadssl'); ?></p>
        </div>
        <?php
    }
    
    /**
     * Set up WordPress hooks
     */
    private function init_hooks() {
        // Get options
        $options = get_option('cadssl_options', array());
        
        // Force SSL if enabled
        if (isset($options['force_ssl']) && $options['force_ssl']) {
            add_action('template_redirect', array($this, 'force_ssl'), 10);
        }
        
        // Set secure cookies
        if (isset($options['secure_cookies']) && $options['secure_cookies']) {
            add_filter('secure_signon_cookie', '__return_true');
            add_filter('wp_set_auth_cookie', array($this, 'set_httponly_secure_cookies'), 10, 6);
        }
        
        // Apply security headers
        if (isset($options['security_headers']) && $options['security_headers']) {
            if (class_exists('CADSSL_Security_Headers')) {
                $security_headers = new CADSSL_Security_Headers();
                $security_headers->apply_security_headers();
            }
        }
        
        // Apply HSTS if enabled
        if (isset($options['enable_hsts']) && $options['enable_hsts']) {
            add_action('send_headers', array($this, 'add_hsts_header'));
        }
    }
    
    /**
     * Force SSL by redirecting HTTP to HTTPS
     */
    public function force_ssl() {
        if (!is_ssl()) {
            wp_redirect('https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'], 301);
            exit;
        }
    }
    
    /**
     * Set secure and HTTPOnly flags for cookies
     */
    public function set_httponly_secure_cookies($cookie1, $cookie2, $expire, $expiration, $user_id, $scheme) {
        if (is_ssl()) {
            add_filter('secure_auth_cookie', '__return_true');
            add_filter('secure_logged_in_cookie', '__return_true');
            
            // Set HTTPOnly
            $_COOKIE[LOGGED_IN_COOKIE] = $cookie1;
            $_COOKIE[AUTH_COOKIE] = $cookie2;
        }
        
        return $cookie1;
    }
    
    /**
     * Add HSTS header for HTTP Strict Transport Security
     */
    public function add_hsts_header() {
        if (is_ssl()) {
            $options = get_option('cadssl_options');
            $max_age = isset($options['hsts_max_age']) ? intval($options['hsts_max_age']) : 31536000; // 1 year default
            $include_subdomains = isset($options['hsts_subdomains']) && $options['hsts_subdomains'] ? '; includeSubDomains' : '';
            $preload = isset($options['hsts_preload']) && $options['hsts_preload'] ? '; preload' : '';
            
            header('Strict-Transport-Security: max-age=' . $max_age . $include_subdomains . $preload);
        }
    }
}
