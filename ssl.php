<?php
/**
 * Plugin Name: CADSSL Security
 * Plugin URI: https://example.com/cadssl
 * Description: Advanced WordPress security plugin with SSL enforcement, security headers, and more.
 * Version: 1.0.0
 * Author: CADSSL Developer
 * Author URI: https://example.com
 * Text Domain: cadssl
 * Domain Path: /languages
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('CADSSL_VERSION', '1.0.0');
define('CADSSL_FILE', __FILE__);  // This fixes the undefined constant error
define('CADSSL_PATH', plugin_dir_path(__FILE__));
define('CADSSL_URL', plugin_dir_url(__FILE__));
define('CADSSL_BASENAME', plugin_basename(__FILE__)); // Add this line to fix the error

// Load error handler first to catch any errors during initialization
require_once CADSSL_PATH . 'includes/class-cadssl-error-handler.php';
$cadssl_error_handler = new CADSSL_Error_Handler();
$cadssl_error_handler->init();

// Include required files - using require_once with error handling
$required_files = array(
    'includes/class-cadssl-core.php',
    'includes/class-cadssl-ssl-checker.php',
    'includes/class-cadssl-security-headers.php',
    'includes/class-cadssl-admin.php',
    'includes/class-cadssl-mixed-content-fixer.php',
    'includes/class-cadssl-certificate-monitor.php',
    'includes/class-cadssl-security-scanner.php',
    'includes/class-cadssl-dashboard.php',
    'includes/class-cadssl-file-permissions.php',
    'includes/class-cadssl-malware-scanner.php',
    'includes/class-cadssl-advanced-headers.php',
    'includes/class-cadssl-gdpr.php',
    'includes/class-cadssl-file-viewer.php',
    'includes/class-cadssl-fallback-ajax.php', // Added fallback AJAX handler
    'includes/class-cadssl-background-scanner.php', // Added background scanner
    'includes/class-cadssl-process-lock.php',       // Added process lock utility
    'includes/ajax-handlers.php'
);

foreach ($required_files as $file) {
    $file_path = CADSSL_PATH . $file;
    if (file_exists($file_path)) {
        require_once $file_path;
    } else {
        // Log missing file but don't break entire site
        error_log('CADSSL Security: Required file missing: ' . $file_path);
    }
}

// Initialize the plugin with error handling
function cadssl_init() {
    try {
        // Initialize admin first to ensure main menu is created before submenus
        if (is_admin()) {
            $cadssl_admin = new CADSSL_Admin();
            $cadssl_admin->init();
        }
        
        // Initialize core functionality
        if (class_exists('CADSSL_Core')) {
            $cadssl_core = new CADSSL_Core();
            $cadssl_core->init();
        }
        
        // Only initialize other components if their classes exist
        if (class_exists('CADSSL_Mixed_Content_Fixer')) {
            $cadssl_mixed_content = new CADSSL_Mixed_Content_Fixer();
            $cadssl_mixed_content->init();
        }
        
        if (class_exists('CADSSL_Certificate_Monitor')) {
            $cadssl_cert_monitor = new CADSSL_Certificate_Monitor();
            $cadssl_cert_monitor->init();
        }
        
        if (class_exists('CADSSL_Security_Scanner')) {
            $cadssl_scanner = new CADSSL_Security_Scanner();
            $cadssl_scanner->init();
        }
        
        if (class_exists('CADSSL_Dashboard')) {
            $cadssl_dashboard = new CADSSL_Dashboard();
            $cadssl_dashboard->init();
        }
        
        if (class_exists('CADSSL_File_Permissions')) {
            $cadssl_file_permissions = new CADSSL_File_Permissions();
            $cadssl_file_permissions->init();
        }
        
        if (class_exists('CADSSL_Malware_Scanner')) {
            $cadssl_malware_scanner = new CADSSL_Malware_Scanner();
            $cadssl_malware_scanner->init();
        }
        
        if (class_exists('CADSSL_Advanced_Headers')) {
            $cadssl_advanced_headers = new CADSSL_Advanced_Headers();
            $cadssl_advanced_headers->init();
        }
        
        if (class_exists('CADSSL_GDPR')) {
            $cadssl_gdpr = new CADSSL_GDPR();
            $cadssl_gdpr->init();
        }
        
        if (class_exists('CADSSL_File_Viewer')) {
            $cadssl_file_viewer = new CADSSL_File_Viewer();
            $cadssl_file_viewer->init();
        }
        
        // Initialize background scanner
        if (class_exists('CADSSL_Background_Scanner')) {
            $cadssl_bg_scanner = new CADSSL_Background_Scanner();
            $cadssl_bg_scanner->init();
        }
        
        // Clean up expired locks once a day
        if (!wp_next_scheduled('cadssl_cleanup_locks')) {
            wp_schedule_event(time(), 'daily', 'cadssl_cleanup_locks');
        }
        add_action('cadssl_cleanup_locks', array('CADSSL_Process_Lock', 'cleanup_expired_locks'));
        
        // Register scripts and styles
        add_action('admin_enqueue_scripts', 'cadssl_register_assets');
    } catch (Exception $e) {
        // Log the error but don't break the site
        error_log('CADSSL Security: Error during initialization: ' . $e->getMessage());
    }
}
add_action('plugins_loaded', 'cadssl_init');

/**
 * Register scripts and styles
 */
function cadssl_register_assets($hook) {
    // Only load on plugin pages
    if (strpos($hook, 'cadssl') === false) {
        return;
    }
    
    // Register and enqueue admin styles
    wp_register_style('cadssl-admin', CADSSL_URL . 'assets/css/admin.css', array(), CADSSL_VERSION);
    wp_enqueue_style('cadssl-admin');
    
    // Register and enqueue prism.js for code highlighting
    if (strpos($hook, 'cadssl-malware-scanner') !== false || strpos($hook, 'cadssl-file-viewer') !== false) {
        wp_register_style('cadssl-prism', CADSSL_URL . 'assets/css/prism.css', array(), CADSSL_VERSION);
        wp_enqueue_style('cadssl-prism');
        
        wp_register_script('cadssl-prism', CADSSL_URL . 'assets/js/prism.js', array(), CADSSL_VERSION, true);
        wp_enqueue_script('cadssl-prism');
    }
    
    // Register malware scanner styles
    if (strpos($hook, 'cadssl-malware-scanner') !== false) {
        wp_register_style('cadssl-malware-scanner', CADSSL_URL . 'assets/css/malware-scanner.css', array(), CADSSL_VERSION);
        wp_enqueue_style('cadssl-malware-scanner');
    }
    
    // Register and enqueue AJAX JavaScript
    wp_register_script('cadssl-ajax', CADSSL_URL . 'assets/js/ajax-handler.js', array('jquery'), CADSSL_VERSION, true);
    wp_localize_script('cadssl-ajax', 'cadssl_ajax', array(
        'ajax_url' => admin_url('admin-ajax.php'),
        'nonce' => wp_create_nonce('cadssl_ajax_nonce')
    ));
    wp_enqueue_script('cadssl-ajax');
    
    // Load page-specific scripts
    if (strpos($hook, 'cadssl-advanced-headers') !== false) {
        wp_register_script('cadssl-advanced-headers', CADSSL_URL . 'assets/js/advanced-headers.js', array('jquery'), CADSSL_VERSION, true);
        wp_localize_script('cadssl-advanced-headers', 'cadssl_ajax', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('cadssl_advanced_headers_nonce')
        ));
        wp_enqueue_script('cadssl-advanced-headers');
    }
    
    if (strpos($hook, 'cadssl-file-permissions') !== false) {
        wp_register_script('cadssl-file-permissions', CADSSL_URL . 'assets/js/file-permissions.js', array('jquery'), CADSSL_VERSION, true);
        wp_localize_script('cadssl-file-permissions', 'cadssl_ajax', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('cadssl_fix_permissions')
        ));
        wp_enqueue_script('cadssl-file-permissions');
    }
    
    if (strpos($hook, 'cadssl-malware-scanner') !== false) {
        wp_register_script('cadssl-malware-scanner', CADSSL_URL . 'assets/js/malware-scanner.js', array('jquery'), CADSSL_VERSION, true);
        wp_localize_script('cadssl-malware-scanner', 'cadssl_scanner', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'start_scan_nonce' => wp_create_nonce('cadssl_start_malware_scan'),
            'process_batch_nonce' => wp_create_nonce('cadssl_process_malware_scan_batch'),
            'get_results_nonce' => wp_create_nonce('cadssl_get_scan_results'),
            'quarantine_nonce' => wp_create_nonce('cadssl_quarantine_file'),
            'restore_nonce' => wp_create_nonce('cadssl_restore_file'),
            'check_interrupted_nonce' => wp_create_nonce('cadssl_check_interrupted_scan'),
            'clear_scan_nonce' => wp_create_nonce('cadssl_clear_interrupted_scan'),
            'get_status_nonce' => wp_create_nonce('cadssl_get_scan_status'),
            'heartbeat_nonce' => wp_create_nonce('cadssl_scan_heartbeat'),
            'interrupt_nonce' => wp_create_nonce('cadssl_mark_scan_interrupted'),
            'resume_scan_nonce' => wp_create_nonce('cadssl_resume_scan'),
            'get_progress_nonce' => wp_create_nonce('cadssl_get_scan_progress'),
            'simple_scan_nonce' => wp_create_nonce('cadssl_simple_scan'), // Added new nonce
            'strings' => array(
                'preparing' => __('Preparing scan...', 'cadssl'),
                'scanning' => __('Scanning files...', 'cadssl'),
                'analyzing' => __('Analyzing results...', 'cadssl'),
                'completed' => __('Scan completed', 'cadssl'),
                'error_scanning' => __('Error during scanning', 'cadssl'),
                'files_scanned' => __('Files scanned:', 'cadssl'),
                'suspicious_found' => __('Suspicious files found:', 'cadssl'),
                'malware_found' => __('Malware detected:', 'cadssl'),
                'start_scan' => __('Start Scan', 'cadssl'),
                'cancel_scan' => __('Cancel Scan', 'cadssl'),
                'quarantine_file' => __('Quarantine File', 'cadssl'),
                'restore_file' => __('Restore File', 'cadssl'),
                'view_file' => __('View File', 'cadssl'),
                'quarantining' => __('Quarantining...', 'cadssl'),
                'restoring' => __('Restoring...', 'cadssl'),
                'file_quarantined' => __('File quarantined successfully', 'cadssl'),
                'file_restored' => __('File restored successfully', 'cadssl'),
                'error_quarantine' => __('Error quarantining file', 'cadssl'),
                'error_restore' => __('Error restoring file', 'cadssl'),
                'scan_interrupted' => __('Scan Interrupted', 'cadssl'),
                'scan_resume_msg' => __('A previous scan was interrupted. Would you like to resume or start a new scan?', 'cadssl'),
                'resume_scan' => __('Resume Scan', 'cadssl'),
                'new_scan' => __('Start New Scan', 'cadssl'),
                'scan_timeout' => __('Scan timed out. You can resume it later.', 'cadssl'),
                'retrying' => __('Connection issue. Retrying...', 'cadssl'),
                'reconnecting' => __('Reconnecting to server...', 'cadssl'),
                'recovering' => __('Recovering from error...', 'cadssl'),
                'timeout_retrying' => __('Server timeout. Retrying with fewer files...', 'cadssl'),
                'processing_files' => __('Processing files', 'cadssl'),
                'processing_file' => __('Processing file:', 'cadssl'),
                'processed_file' => __('Processed file:', 'cadssl'),
                'connection_error' => __('Connection error. The scan was interrupted but can be resumed later.', 'cadssl'),
                'recovery_failed' => __('Recovery failed after multiple attempts. Please try again later.', 'cadssl'),
                'completed' => __('completed', 'cadssl'),
                'retrying_in' => __('Retrying in', 'cadssl'),
                'falling_back' => __('Switching to fallback mode...', 'cadssl'),
                'using_fallback' => __('Using fallback scanning mode for stability', 'cadssl'),
                'skipping_file' => __('Skipping problematic file', 'cadssl'),
            )
        ));
        wp_enqueue_script('cadssl-malware-scanner');
    }
}

// Activation hook with error handling
function cadssl_activate() {
    try {
        // Set default options
        $default_options = array(
            'force_ssl' => true,
            'enable_hsts' => false,
            'security_headers' => true,
            'secure_cookies' => true,
            'auto_fix_mixed_content' => true,
            'cert_expiry_notify' => true,
            'cert_expiry_threshold' => 14,
            'security_scan_notify' => true,
            'permissions_scan_notify' => true,
            'malware_scan_notify' => true,
        );
        
        add_option('cadssl_options', $default_options);
        
        // Set default GDPR options
        $default_gdpr_options = array(
            'enable_gdpr_features' => false,
            'enable_cookie_notice' => false,
            'cookie_notice_text' => __('This website uses cookies to ensure you get the best experience on our website.', 'cadssl'),
            'enable_privacy_policy_link' => false,
            'cookie_expiration_days' => 14,
            'data_retention_period' => 0,
            'enable_data_access' => true,
            'enable_data_deletion' => true,
        );
        
        add_option('cadssl_gdpr_options', $default_gdpr_options);
        
        // Set default advanced headers options
        $default_headers_options = array(
            'enable_advanced_headers' => false,
            'enable_csp' => false,
            'csp_mode' => 'report-only',
            'csp_policy' => "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;",
            'enable_xss_protection' => true,
            'enable_content_type_options' => true,
            'enable_frame_options' => true,
            'frame_options_value' => 'SAMEORIGIN',
            'enable_referrer_policy' => true,
            'referrer_policy_value' => 'strict-origin-when-cross-origin',
            'enable_permissions_policy' => false,
            'permissions_policy_value' => "camera=(); microphone=(); geolocation=(); payment=()",
            'enable_clear_site_data' => false,
            'enable_coep' => false,
            'enable_coop' => false,
            'coep_value' => 'require-corp',
            'coop_value' => 'same-origin',
            'enable_corp' => false,
            'corp_value' => 'same-origin'
        );
        
        add_option('cadssl_advanced_headers_options', $default_headers_options);
        
        // Check if site is already using SSL
        $is_ssl = is_ssl();
        update_option('cadssl_ssl_detected', $is_ssl);
        
        // Create quarantine directory for malware scanner
        $quarantine_dir = CADSSL_PATH . 'quarantine';
        if (!file_exists($quarantine_dir)) {
            wp_mkdir_p($quarantine_dir);
            
            // Protect directory with .htaccess
            $htaccess = $quarantine_dir . '/.htaccess';
            file_put_contents($htaccess, "Order deny,allow\nDeny from all");
            
            // Add empty index.php file
            file_put_contents($quarantine_dir . '/index.php', "<?php\n// Silence is golden.");
        }
        
        // Create assets directories if they don't exist
        $assets_dir = CADSSL_PATH . 'assets';
        $css_dir = $assets_dir . '/css';
        $js_dir = $assets_dir . '/js';
        
        if (!file_exists($assets_dir)) {
            wp_mkdir_p($assets_dir);
        }
        
        if (!file_exists($css_dir)) {
            wp_mkdir_p($css_dir);
        }
        
        if (!file_exists($js_dir)) {
            wp_mkdir_p($js_dir);
        }
        
        // Flush rewrite rules for potential redirects
        flush_rewrite_rules();
    } catch (Exception $e) {
        error_log('CADSSL Security: Error during activation: ' . $e->getMessage());
    }
}
register_activation_hook(__FILE__, 'cadssl_activate');

// Deactivation hook with error handling
function cadssl_deactivate() {
    try {
        // Clear scheduled events
        wp_clear_scheduled_hook('cadssl_daily_certificate_check');
        wp_clear_scheduled_hook('cadssl_weekly_security_scan');
        wp_clear_scheduled_hook('cadssl_weekly_permissions_scan');
        wp_clear_scheduled_hook('cadssl_weekly_malware_scan');
        wp_clear_scheduled_hook('cadssl_weekly_data_retention');
        
        // Don't remove settings on deactivation to preserve user configuration
        
        // Flush rewrite rules
        flush_rewrite_rules();
    } catch (Exception $e) {
        error_log('CADSSL Security: Error during deactivation: ' . $e->getMessage());
    }
}
register_deactivation_hook(__FILE__, 'cadssl_deactivate');

// Add missing class definition if needed
if (!class_exists('CADSSL_Security_Headers')) {
    class CADSSL_Security_Headers {
        public function apply_security_headers() {
            // Default implementation to prevent fatal errors
            add_action('send_headers', function() {
                // Minimal security headers
                header('X-Content-Type-Options: nosniff');
                header('X-XSS-Protection: 1; mode=block');
                header('X-Frame-Options: SAMEORIGIN');
            });
        }
    }
}

// Add missing class definition if needed
if (!class_exists('CADSSL_Mixed_Content_Fixer')) {
    class CADSSL_Mixed_Content_Fixer {
        public function init() {
            // Minimal implementation to prevent errors
        }
    }
}

// Add missing class definition if needed
if (!class_exists('CADSSL_Security_Scanner')) {
    class CADSSL_Security_Scanner {
        public function init() {
            // Minimal implementation to prevent errors
        }
        
        public function run_security_scan() {
            // Minimal implementation to prevent errors
            return array();
        }
    }
}

// Debug functionality for troubleshooting
function cadssl_debug_info() {
    if (current_user_can('administrator')) {
        // Check if all required classes exist
        $required_classes = array(
            'CADSSL_Core',
            'CADSSL_SSL_Checker',
            'CADSSL_Security_Headers',
            'CADSSL_Admin',
            'CADSSL_Mixed_Content_Fixer',
            'CADSSL_Certificate_Monitor',
            'CADSSL_Security_Scanner',
            'CADSSL_Dashboard',
            'CADSSL_File_Permissions',
            'CADSSL_Malware_Scanner',
            'CADSSL_Advanced_Headers',
            'CADSSL_GDPR',
            'CADSSL_File_Viewer'
        );
        
        $missing_classes = array();
        foreach ($required_classes as $class) {
            if (!class_exists($class)) {
                $missing_classes[] = $class;
            }
        }
        
        if (!empty($missing_classes)) {
            echo '<div class="error"><p><strong>CADSSL Security Debug:</strong> Missing classes: ' . implode(', ', $missing_classes) . '</p></div>';
        }
    }
}
add_action('admin_notices', 'cadssl_debug_info');
