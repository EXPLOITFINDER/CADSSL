<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * CADSSL Ajax Handlers
 * Handles all AJAX requests for the plugin
 */
class CADSSL_Ajax_Handlers {
    /**
     * Initialize Ajax handlers
     */
    public function init() {
        // Advanced headers AJAX handler
        add_action('wp_ajax_cadssl_save_advanced_headers', array($this, 'save_advanced_headers'));
        
        // File permissions AJAX handler
        add_action('wp_ajax_cadssl_fix_permissions', array($this, 'fix_permissions'));
        
        // Security scanner AJAX handler
        add_action('wp_ajax_cadssl_run_security_scan', array($this, 'run_security_scan'));
    }
    
    /**
     * Save advanced headers
     */
    public function save_advanced_headers() {
        try {
            // Verify nonce
            if (!isset($_POST['security']) || !wp_verify_nonce($_POST['security'], 'cadssl_advanced_headers_nonce')) {
                throw new Exception(__('Security check failed.', 'cadssl'));
            }
            
            // Check user capabilities
            if (!current_user_can('manage_options')) {
                throw new Exception(__('You do not have permission to perform this action.', 'cadssl'));
            }
            
            // Parse form data
            $form_data = array();
            parse_str($_POST['form_data'], $form_data);
            
            if (!isset($form_data['cadssl_advanced_headers_options'])) {
                throw new Exception(__('Invalid form data.', 'cadssl'));
            }
            
            $options = $form_data['cadssl_advanced_headers_options'];
            
            // Validate and sanitize options
            $sanitized_options = $this->sanitize_advanced_headers_options($options);
            
            // Update options
            update_option('cadssl_advanced_headers_options', $sanitized_options);
            
            // Send success response
            wp_send_json_success(array('message' => __('Advanced headers settings saved successfully.', 'cadssl')));
        } catch (Exception $e) {
            // Log error and send error response
            error_log('CADSSL Advanced Headers AJAX error: ' . $e->getMessage());
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }
    
    /**
     * Sanitize advanced headers options
     * 
     * @param array $options Options to sanitize
     * @return array Sanitized options
     */
    private function sanitize_advanced_headers_options($options) {
        $sanitized = array();
        
        // Boolean fields
        $boolean_fields = array(
            'enable_advanced_headers',
            'enable_csp',
            'enable_xss_protection',
            'enable_content_type_options',
            'enable_frame_options',
            'enable_referrer_policy',
            'enable_permissions_policy',
            'enable_clear_site_data',
            'enable_coep',
            'enable_coop',
            'enable_corp'
        );
        
        foreach ($boolean_fields as $field) {
            $sanitized[$field] = isset($options[$field]) ? (bool) $options[$field] : false;
        }
        
        // Text fields with specific sanitization
        if (isset($options['csp_policy'])) {
            $sanitized['csp_policy'] = sanitize_textarea_field($options['csp_policy']);
        }
        
        if (isset($options['permissions_policy_value'])) {
            $sanitized['permissions_policy_value'] = sanitize_textarea_field($options['permissions_policy_value']);
        }
        
        // Select fields
        $select_fields = array(
            'csp_mode',
            'frame_options_value',
            'referrer_policy_value',
            'coep_value',
            'coop_value',
            'corp_value'
        );
        
        foreach ($select_fields as $field) {
            if (isset($options[$field])) {
                $sanitized[$field] = sanitize_text_field($options[$field]);
            }
        }
        
        return $sanitized;
    }
    
    /**
     * Fix file permissions
     */
    public function fix_permissions() {
        try {
            // Verify nonce
            if (!isset($_POST['security']) || !wp_verify_nonce($_POST['security'], 'cadssl_fix_permissions')) {
                throw new Exception(__('Security check failed.', 'cadssl'));
            }
            
            // Check user capabilities
            if (!current_user_can('manage_options')) {
                throw new Exception(__('You do not have permission to perform this action.', 'cadssl'));
            }
            
            // Get files to fix
            $files = isset($_POST['files']) ? $_POST['files'] : array();
            
            if (empty($files)) {
                throw new Exception(__('No files selected.', 'cadssl'));
            }
            
            // Initialize file permissions class
            if (!class_exists('CADSSL_File_Permissions')) {
                require_once CADSSL_PATH . 'includes/class-cadssl-file-permissions.php';
            }
            
            $file_permissions = new CADSSL_File_Permissions();
            
            // Fix file permissions
            $results = $file_permissions->fix_file_permissions($files);
            
            // Send response
            wp_send_json_success(array(
                'message' => sprintf(
                    __('Fixed %d file(s). %d file(s) failed.', 'cadssl'),
                    $results['fixed'],
                    $results['failed']
                ),
                'results' => $results
            ));
        } catch (Exception $e) {
            // Log error and send error response
            error_log('CADSSL Fix Permissions AJAX error: ' . $e->getMessage());
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }
    
    /**
     * Run security scan
     */
    public function run_security_scan() {
        try {
            // Verify nonce
            if (!isset($_POST['security']) || !wp_verify_nonce($_POST['security'], 'cadssl_security_scan')) {
                throw new Exception(__('Security check failed.', 'cadssl'));
            }
            
            // Check user capabilities
            if (!current_user_can('manage_options')) {
                throw new Exception(__('You do not have permission to perform this action.', 'cadssl'));
            }
            
            // Initialize security scanner class
            if (!class_exists('CADSSL_Security_Scanner')) {
                require_once CADSSL_PATH . 'includes/class-cadssl-security-scanner.php';
            }
            
            $security_scanner = new CADSSL_Security_Scanner();
            
            // Run security scan
            $results = $security_scanner->run_security_scan();
            
            // Update options
            update_option('cadssl_last_scan_results', $results);
            update_option('cadssl_last_scan_time', date('Y-m-d H:i:s'));
            
            // Send response
            wp_send_json_success($results);
        } catch (Exception $e) {
            // Log error and send error response
            error_log('CADSSL Security Scan AJAX error: ' . $e->getMessage());
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }
}

// Initialize AJAX handlers
$cadssl_ajax_handlers = new CADSSL_Ajax_Handlers();
$cadssl_ajax_handlers->init();
