<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class CADSSL_Security_Scanner {
    /**
     * Initialize security scanner
     */
    public function init() {
        // Add admin menu
        add_action('admin_menu', array($this, 'add_scanner_menu'), 19); // Higher priority to run after main menu
        
        // Schedule weekly security scan
        add_action('cadssl_weekly_security_scan', array($this, 'run_automated_scan'));
        
        // Set up schedule if not already scheduled
        if (!wp_next_scheduled('cadssl_weekly_security_scan')) {
            wp_schedule_event(time(), 'weekly', 'cadssl_weekly_security_scan');
        }
        
        // Add AJAX handler for scan operations
        add_action('wp_ajax_cadssl_run_security_scan', array($this, 'ajax_run_security_scan'));
    }
    
    /**
     * AJAX handler for security scan
     */
    public function ajax_run_security_scan() {
        // Verify nonce
        check_ajax_referer('cadssl_security_scan', 'security');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }
        
        try {
            $results = $this->run_security_scan();
            update_option('cadssl_last_scan_results', $results);
            update_option('cadssl_last_scan_time', date('Y-m-d H:i:s'));
            wp_send_json_success($results);
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
    }
    
    /**
     * Add scanner submenu
     */
    public function add_scanner_menu() {
        // Make sure the parent menu exists before adding submenu
        global $submenu;
        if (isset($submenu['cadssl-settings'])) {
            add_submenu_page(
                'cadssl-settings', 
                __('Security Scanner', 'cadssl'),
                __('Security Scanner', 'cadssl'),
                'manage_options',
                'cadssl-security-scanner',
                array($this, 'display_scanner_page')
            );
        } else {
            // Fallback if parent menu doesn't exist yet
            add_menu_page(
                __('Security Scanner', 'cadssl'),
                __('Security Scanner', 'cadssl'),
                'manage_options',
                'cadssl-security-scanner',
                array($this, 'display_scanner_page'),
                'dashicons-shield',
                100
            );
        }
    }
    
    /**
     * Display security scanner page
     */
    public function display_scanner_page() {
        // Get the last scan results if available
        $scan_results = get_option('cadssl_last_scan_results', array());
        $last_scan_time = get_option('cadssl_last_scan_time');
        
        ?>
        <div class="wrap">
            <h1><?php _e('Security Scanner', 'cadssl'); ?></h1>
            
            <div class="card">
                <h2><?php _e('Run Security Scan', 'cadssl'); ?></h2>
                <p><?php _e('This will scan your WordPress installation for security issues.', 'cadssl'); ?></p>
                
                <?php if ($last_scan_time): ?>
                <p>
                    <?php 
                    printf(
                        __('Last scan: %s', 'cadssl'),
                        date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($last_scan_time))
                    ); 
                    ?>
                </p>
                <?php endif; ?>
                
                <p>
                    <button type="button" id="cadssl-run-scan" class="button button-primary">
                        <?php _e('Run Security Scan', 'cadssl'); ?>
                    </button>
                    <span id="cadssl-scan-spinner" class="spinner" style="float:none;"></span>
                </p>
                
                <div id="cadssl-scan-progress" style="display:none;">
                    <p><?php _e('Scanning... Please wait.', 'cadssl'); ?></p>
                    <div class="cadssl-progress-bar">
                        <div class="cadssl-progress-bar-inner"></div>
                    </div>
                </div>
                
                <div id="cadssl-scan-error" class="notice notice-error" style="display:none;">
                    <p></p>
                </div>
            </div>
            
            <div id="cadssl-scan-results">
                <?php $this->display_scan_results($scan_results); ?>
            </div>
        </div>
        
        <script type="text/javascript">
            jQuery(document).ready(function($) {
                $('#cadssl-run-scan').on('click', function() {
                    // Show spinner and progress bar
                    $('#cadssl-scan-spinner').addClass('is-active');
                    $('#cadssl-scan-progress').show();
                    $('#cadssl-scan-error').hide();
                    
                    // Disable button
                    $(this).prop('disabled', true);
                    
                    // Start the scan
                    $.ajax({
                        url: ajaxurl,
                        type: 'POST',
                        data: {
                            action: 'cadssl_run_security_scan',
                            security: '<?php echo wp_create_nonce('cadssl_security_scan'); ?>'
                        },
                        success: function(response) {
                            // Hide spinner and progress
                            $('#cadssl-scan-spinner').removeClass('is-active');
                            $('#cadssl-scan-progress').hide();
                            
                            // Re-enable button
                            $('#cadssl-run-scan').prop('disabled', false);
                            
                            if (response.success) {
                                // Reload the page to show new results
                                location.reload();
                            } else {
                                // Show error
                                $('#cadssl-scan-error').show().find('p').text('Error: ' + (response.data || 'Unknown error'));
                            }
                        },
                        error: function(jqXHR, textStatus, errorThrown) {
                            // Hide spinner and progress
                            $('#cadssl-scan-spinner').removeClass('is-active');
                            $('#cadssl-scan-progress').hide();
                            
                            // Re-enable button
                            $('#cadssl-run-scan').prop('disabled', false);
                            
                            // Show error
                            $('#cadssl-scan-error').show().find('p').text('Error: ' + errorThrown);
                        }
                    });
                });
            });
        </script>
        
        <style>
            .cadssl-progress-bar {
                height: 20px;
                background-color: #f0f0f0;
                border-radius: 4px;
                margin: 10px 0;
            }
            .cadssl-progress-bar-inner {
                height: 20px;
                background-color: #2271b1;
                border-radius: 4px;
                width: 0%;
                animation: cadssl-progress 2s infinite linear;
            }
            @keyframes cadssl-progress {
                0% { width: 0%; }
                50% { width: 50%; }
                100% { width: 100%; }
            }
        </style>
        <?php
    }
    
    /**
     * Display scan results
     * 
     * @param array $scan_results Security scan results
     */
    public function display_scan_results($scan_results) {
        if (empty($scan_results)) {
            echo '<div class="notice notice-info"><p>' . __('No scan results available. Please run a security scan.', 'cadssl') . '</p></div>';
            return;
        }
        
        echo '<h2>' . __('Scan Results', 'cadssl') . '</h2>';
        
        // Display each category of results
        foreach ($scan_results as $section => $items) {
            if (empty($items)) {
                continue;
            }
            
            // Section title
            $section_title = ucfirst(str_replace('_', ' ', $section));
            echo '<h3>' . esc_html($section_title) . '</h3>';
            
            echo '<table class="wp-list-table widefat fixed striped">';
            echo '<thead><tr>';
            echo '<th>' . __('Item', 'cadssl') . '</th>';
            echo '<th>' . __('Status', 'cadssl') . '</th>';
            echo '<th>' . __('Description', 'cadssl') . '</th>';
            echo '<th>' . __('Actions', 'cadssl') . '</th>';
            echo '</tr></thead>';
            echo '<tbody>';
            
            foreach ($items as $item) {
                // Ensure we have all required keys to prevent errors
                $item = wp_parse_args($item, array(
                    'title' => '',
                    'status' => 'info',
                    'description' => '',
                    'action_url' => '',
                    'action_text' => ''
                ));
                
                $status_class = '';
                $status_icon = '';
                
                switch ($item['status']) {
                    case 'success':
                        $status_class = 'notice-success';
                        $status_icon = '✓';
                        break;
                    case 'warning':
                        $status_class = 'notice-warning';
                        $status_icon = '⚠';
                        break;
                    case 'critical':
                        $status_class = 'notice-error';
                        $status_icon = '✗';
                        break;
                    default:
                        $status_class = '';
                        $status_icon = '•';
                }
                
                echo '<tr>';
                echo '<td>' . esc_html($item['title']) . '</td>';
                echo '<td><span class="' . esc_attr($status_class) . '">' . $status_icon . '</span></td>';
                echo '<td>' . esc_html($item['description']) . '</td>';
                echo '<td>';
                
                if (!empty($item['action_url']) && !empty($item['action_text'])) {
                    echo '<a href="' . esc_url($item['action_url']) . '" class="button button-small">';
                    echo esc_html($item['action_text']);
                    echo '</a>';
                }
                
                echo '</td>';
                echo '</tr>';
            }
            
            echo '</tbody></table>';
        }
    }
    
    /**
     * Run security scan
     * 
     * @return array Scan results
     */
    public function run_security_scan() {
        try {
            $results = array(
                'wordpress' => $this->check_wordpress_security(),
                'ssl' => $this->check_ssl_security(),
                'file_permissions' => $this->check_file_permissions(),
                'plugins' => $this->check_plugin_security(),
                'users' => $this->check_user_security()
            );
            
            // Allow other components to add checks
            return apply_filters('cadssl_security_scan_results', $results);
            
        } catch (Exception $e) {
            error_log('CADSSL Security Scanner error: ' . $e->getMessage());
            return array(
                'error' => array(
                    array(
                        'title' => __('Scan Error', 'cadssl'),
                        'status' => 'critical',
                        'description' => $e->getMessage()
                    )
                )
            );
        }
    }
    
    /**
     * Run automated security scan and notify admin of issues
     */
    public function run_automated_scan() {
        try {
            $results = $this->run_security_scan();
            update_option('cadssl_last_scan_results', $results);
            update_option('cadssl_last_scan_time', date('Y-m-d H:i:s'));
            
            // Check if there are any critical issues
            $critical_issues = 0;
            foreach ($results as $category => $items) {
                foreach ($items as $item) {
                    if (isset($item['status']) && $item['status'] === 'critical') {
                        $critical_issues++;
                    }
                }
            }
            
            // Send email notification if there are critical issues
            if ($critical_issues > 0) {
                $options = get_option('cadssl_options', array());
                if (isset($options['security_scan_notify']) && $options['security_scan_notify']) {
                    $admin_email = get_option('admin_email');
                    $site_url = get_site_url();
                    $subject = sprintf(__('Security Issues Detected: %s', 'cadssl'), parse_url($site_url, PHP_URL_HOST));
                    
                    $message = sprintf(
                        __('The automated security scan for your WordPress site %1$s has detected %2$d critical security issues that need your attention. Please login to your WordPress admin panel and check the Security Scanner results.', 'cadssl'),
                        $site_url,
                        $critical_issues
                    );
                    
                    $headers = array('Content-Type: text/html; charset=UTF-8');
                    
                    wp_mail($admin_email, $subject, $message, $headers);
                }
            }
        } catch (Exception $e) {
            error_log('CADSSL Automated Security Scan error: ' . $e->getMessage());
        }
    }
    
    /**
     * Check WordPress security
     * 
     * @return array Security check results
     */
    private function check_wordpress_security() {
        $results = array();
        
        try {
            // Check WordPress version
            global $wp_version;
            $latest_wp_version = $this->get_latest_wp_version();
            
            if ($latest_wp_version && version_compare($wp_version, $latest_wp_version, '<')) {
                $results[] = array(
                    'title' => __('WordPress Version', 'cadssl'),
                    'status' => 'critical',
                    'description' => sprintf(__('Your WordPress version (%s) is outdated. The latest version is %s.', 'cadssl'), $wp_version, $latest_wp_version),
                    'action_url' => admin_url('update-core.php'),
                    'action_text' => __('Update Now', 'cadssl')
                );
            } else {
                $results[] = array(
                    'title' => __('WordPress Version', 'cadssl'),
                    'status' => 'success',
                    'description' => sprintf(__('Your WordPress version (%s) is up to date.', 'cadssl'), $wp_version),
                    'action_url' => '',
                    'action_text' => ''
                );
            }
            
            // Check file editing
            $disallow_file_edit = defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT;
            
            $results[] = array(
                'title' => __('File Editing', 'cadssl'),
                'status' => $disallow_file_edit ? 'success' : 'warning',
                'description' => $disallow_file_edit ? 
                    __('File editing is disabled.', 'cadssl') : 
                    __('File editing is enabled. For better security, disable file editing in wp-config.php.', 'cadssl'),
                'action_url' => 'https://wordpress.org/documentation/article/editing-wp-config-php/#disable-the-plugin-and-theme-file-editor',
                'action_text' => __('Learn More', 'cadssl')
            );
            
            // Check debug mode
            $debug_mode = defined('WP_DEBUG') && WP_DEBUG;
            
            $results[] = array(
                'title' => __('Debug Mode', 'cadssl'),
                'status' => !$debug_mode ? 'success' : 'warning',
                'description' => !$debug_mode ? 
                    __('Debug mode is disabled.', 'cadssl') : 
                    __('Debug mode is enabled. This should be disabled on production sites.', 'cadssl'),
                'action_url' => 'https://wordpress.org/documentation/article/debugging-in-wordpress/',
                'action_text' => __('Learn More', 'cadssl')
            );
        } catch (Exception $e) {
            error_log('CADSSL WordPress Security Check error: ' . $e->getMessage());
            $results[] = array(
                'title' => __('WordPress Check Error', 'cadssl'),
                'status' => 'warning',
                'description' => __('An error occurred during the WordPress security check.', 'cadssl'),
                'action_url' => '',
                'action_text' => ''
            );
        }
        
        return $results;
    }
    
    /**
     * Check SSL security
     * 
     * @return array Security check results
     */
    private function check_ssl_security() {
        $results = array();
        
        try {
            // Check if SSL is active
            $is_ssl = is_ssl();
            
            $results[] = array(
                'title' => __('SSL Active', 'cadssl'),
                'status' => $is_ssl ? 'success' : 'critical',
                'description' => $is_ssl ? 
                    __('SSL is active.', 'cadssl') : 
                    __('SSL is not active. Enable SSL for better security.', 'cadssl'),
                'action_url' => admin_url('admin.php?page=cadssl-ssl-status'),
                'action_text' => __('SSL Settings', 'cadssl')
            );
            
            if ($is_ssl) {
                // Check if WordPress URLs use HTTPS
                $site_url_https = strpos(site_url(), 'https://') === 0;
                $home_url_https = strpos(home_url(), 'https://') === 0;
                
                $results[] = array(
                    'title' => __('WordPress URLs', 'cadssl'),
                    'status' => ($site_url_https && $home_url_https) ? 'success' : 'warning',
                    'description' => ($site_url_https && $home_url_https) ? 
                        __('WordPress URLs are using HTTPS.', 'cadssl') : 
                        __('WordPress URLs are not using HTTPS. Update them in Settings > General.', 'cadssl'),
                    'action_url' => admin_url('options-general.php'),
                    'action_text' => __('Settings', 'cadssl')
                );
                
                // Check if HSTS is enabled
                $options = get_option('cadssl_options', array());
                $hsts_enabled = isset($options['enable_hsts']) && $options['enable_hsts'];
                
                $results[] = array(
                    'title' => __('HSTS', 'cadssl'),
                    'status' => $hsts_enabled ? 'success' : 'warning',
                    'description' => $hsts_enabled ? 
                        __('HTTP Strict Transport Security (HSTS) is enabled.', 'cadssl') : 
                        __('HSTS is not enabled. Consider enabling it for better security.', 'cadssl'),
                    'action_url' => admin_url('admin.php?page=cadssl-settings'),
                    'action_text' => __('Settings', 'cadssl')
                );
            }
        } catch (Exception $e) {
            error_log('CADSSL SSL Security Check error: ' . $e->getMessage());
            $results[] = array(
                'title' => __('SSL Check Error', 'cadssl'),
                'status' => 'warning',
                'description' => __('An error occurred during the SSL security check.', 'cadssl'),
                'action_url' => '',
                'action_text' => ''
            );
        }
        
        return $results;
    }
    
    /**
     * Check file permissions
     * 
     * @return array Security check results
     */
    private function check_file_permissions() {
        $results = array();
        
        try {
            // Check wp-config.php permissions
            $wp_config_file = ABSPATH . 'wp-config.php';
            if (file_exists($wp_config_file)) {
                $wp_config_perms = substr(sprintf('%o', fileperms($wp_config_file)), -4);
                $wp_config_secure = octdec($wp_config_perms) <= 0600; // 0600 or more restrictive
                
                $results[] = array(
                    'title' => __('wp-config.php Permissions', 'cadssl'),
                    'status' => $wp_config_secure ? 'success' : 'critical',
                    'description' => $wp_config_secure ? 
                        __('wp-config.php has secure permissions.', 'cadssl') : 
                        sprintf(__('wp-config.php has insecure permissions (%s). Recommended: 0600.', 'cadssl'), $wp_config_perms),
                    'action_url' => admin_url('admin.php?page=cadssl-file-permissions'),
                    'action_text' => __('Fix Permissions', 'cadssl')
                );
            }
            
            // Check uploads directory permissions
            $uploads_dir = wp_upload_dir();
            if (isset($uploads_dir['basedir']) && file_exists($uploads_dir['basedir'])) {
                $uploads_perms = substr(sprintf('%o', fileperms($uploads_dir['basedir'])), -4);
                // For directories, we check if world-writable
                $uploads_secure = !(octdec($uploads_perms) & 0002);
                
                $results[] = array(
                    'title' => __('Uploads Directory Permissions', 'cadssl'),
                    'status' => $uploads_secure ? 'success' : 'warning',
                    'description' => $uploads_secure ? 
                        __('Uploads directory has secure permissions.', 'cadssl') : 
                        __('Uploads directory is world-writable.', 'cadssl'),
                    'action_url' => admin_url('admin.php?page=cadssl-file-permissions'),
                    'action_text' => __('Fix Permissions', 'cadssl')
                );
            }
        } catch (Exception $e) {
            error_log('CADSSL File Permissions Check error: ' . $e->getMessage());
            $results[] = array(
                'title' => __('File Permissions Check Error', 'cadssl'),
                'status' => 'warning',
                'description' => __('An error occurred during the file permissions check.', 'cadssl'),
                'action_url' => '',
                'action_text' => ''
            );
        }
        
        return $results;
    }
    
    /**
     * Check plugin security
     * 
     * @return array Security check results
     */
    private function check_plugin_security() {
        $results = array();
        
        try {
            // Check for inactive plugins
            if (!function_exists('get_plugins')) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            
            $all_plugins = get_plugins();
            $active_plugins = get_option('active_plugins', array());
            $inactive_plugins = array_diff(array_keys($all_plugins), $active_plugins);
            
            if (count($inactive_plugins) > 0) {
                $results[] = array(
                    'title' => __('Inactive Plugins', 'cadssl'),
                    'status' => 'warning',
                    'description' => sprintf(__('You have %d inactive plugins. Inactive plugins should be removed to reduce security risks.', 'cadssl'), count($inactive_plugins)),
                    'action_url' => admin_url('plugins.php'),
                    'action_text' => __('Manage Plugins', 'cadssl')
                );
            } else {
                $results[] = array(
                    'title' => __('Inactive Plugins', 'cadssl'),
                    'status' => 'success',
                    'description' => __('No inactive plugins detected.', 'cadssl'),
                    'action_url' => '',
                    'action_text' => ''
                );
            }
            
            // Check for plugin updates
            $update_plugins = get_site_transient('update_plugins');
            if ($update_plugins && !empty($update_plugins->response)) {
                $results[] = array(
                    'title' => __('Plugin Updates', 'cadssl'),
                    'status' => 'critical',
                    'description' => sprintf(__('You have %d plugins that need updates. Outdated plugins can contain security vulnerabilities.', 'cadssl'), count($update_plugins->response)),
                    'action_url' => admin_url('plugins.php'),
                    'action_text' => __('Update Plugins', 'cadssl')
                );
            } else {
                $results[] = array(
                    'title' => __('Plugin Updates', 'cadssl'),
                    'status' => 'success',
                    'description' => __('All plugins are up to date.', 'cadssl'),
                    'action_url' => '',
                    'action_text' => ''
                );
            }
        } catch (Exception $e) {
            error_log('CADSSL Plugin Security Check error: ' . $e->getMessage());
            $results[] = array(
                'title' => __('Plugin Check Error', 'cadssl'),
                'status' => 'warning',
                'description' => __('An error occurred during the plugin security check.', 'cadssl'),
                'action_url' => '',
                'action_text' => ''
            );
        }
        
        return $results;
    }
    
    /**
     * Check user security
     * 
     * @return array Security check results
     */
    private function check_user_security() {
        $results = array();
        
        try {
            // Check for default admin user
            $user = get_user_by('login', 'admin');
            if ($user) {
                $results[] = array(
                    'title' => __('Admin Username', 'cadssl'),
                    'status' => 'warning',
                    'description' => __('Your site has a user with the default "admin" username which is a security risk.', 'cadssl'),
                    'action_url' => admin_url('users.php'),
                    'action_text' => __('Manage Users', 'cadssl')
                );
            } else {
                $results[] = array(
                    'title' => __('Admin Username', 'cadssl'),
                    'status' => 'success',
                    'description' => __('No user with the default "admin" username detected.', 'cadssl'),
                    'action_url' => '',
                    'action_text' => ''
                );
            }
            
            // Check if there are users with weak passwords (dummy check - can't actually test this)
            $results[] = array(
                'title' => __('Password Strength', 'cadssl'),
                'status' => 'info',
                'description' => __('Ensure all users have strong passwords. WordPress cannot verify password strength for existing accounts.', 'cadssl'),
                'action_url' => admin_url('users.php'),
                'action_text' => __('Manage Users', 'cadssl')
            );
        } catch (Exception $e) {
            error_log('CADSSL User Security Check error: ' . $e->getMessage());
            $results[] = array(
                'title' => __('User Check Error', 'cadssl'),
                'status' => 'warning',
                'description' => __('An error occurred during the user security check.', 'cadssl'),
                'action_url' => '',
                'action_text' => ''
            );
        }
        
        return $results;
    }
    
    /**
     * Get the latest WordPress version
     * 
     * @return string|null Latest WordPress version or null if not available
     */
    private function get_latest_wp_version() {
        try {
            $response = wp_remote_get('https://api.wordpress.org/core/version-check/1.7/');
            
            if (is_wp_error($response)) {
                return null;
            }
            
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);
            
            if (isset($data['offers']) && is_array($data['offers']) && !empty($data['offers']) && isset($data['offers'][0]['current'])) {
                return $data['offers'][0]['current'];
            }
        } catch (Exception $e) {
            error_log('CADSSL get_latest_wp_version error: ' . $e->getMessage());
        }
        
        return null;
    }
}
