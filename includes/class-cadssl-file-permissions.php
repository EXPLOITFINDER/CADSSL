<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * File Permissions Scanner
 * Scans and fixes insecure file permissions
 */
class CADSSL_File_Permissions {
    /**
     * Initialize file permissions functionality
     */
    public function init() {
        // Add admin menu
        add_action('admin_menu', array($this, 'add_file_permissions_menu'), 20);
        
        // Schedule weekly permissions scan
        add_action('cadssl_weekly_permissions_scan', array($this, 'run_automated_scan'));
        
        // Set up schedule if not already scheduled
        if (!wp_next_scheduled('cadssl_weekly_permissions_scan')) {
            wp_schedule_event(time(), 'weekly', 'cadssl_weekly_permissions_scan');
        }
        
        // Ajax handler for fixing permissions
        add_action('wp_ajax_cadssl_fix_permissions', array($this, 'ajax_fix_permissions'));
    }
    
    /**
     * Add file permissions submenu
     */
    public function add_file_permissions_menu() {
        // Make sure the parent menu exists
        global $submenu;
        if (!isset($submenu['cadssl-settings'])) {
            return;
        }
        
        add_submenu_page(
            'cadssl-settings',
            __('File Permissions', 'cadssl'),
            __('File Permissions', 'cadssl'),
            'manage_options',
            'cadssl-file-permissions',
            array($this, 'display_file_permissions_page')
        );
    }
    
    /**
     * Display file permissions page
     */
    public function display_file_permissions_page() {
        // Process scan request
        $scan_results = null;
        if (isset($_POST['cadssl_run_scan']) && isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], 'cadssl_file_permissions_scan')) {
            $scan_results = $this->scan_file_permissions();
            update_option('cadssl_last_permissions_scan', $scan_results);
            update_option('cadssl_last_permissions_scan_time', date('Y-m-d H:i:s'));
        } else {
            // Get last scan results if available
            $scan_results = get_option('cadssl_last_permissions_scan');
        }
        
        ?>
        <div class="wrap">
            <h1><?php _e('File Permissions Scanner', 'cadssl'); ?></h1>
            
            <div class="card">
                <h2><?php _e('About File Permissions', 'cadssl'); ?></h2>
                <p>
                    <?php _e('Proper file permissions are critical for WordPress security. Too permissive settings can allow attackers to modify your files.', 'cadssl'); ?>
                </p>
                <p>
                    <?php _e('Recommended permissions:', 'cadssl'); ?>
                </p>
                <ul>
                    <li><?php _e('WordPress directories: 755', 'cadssl'); ?></li>
                    <li><?php _e('WordPress files: 644', 'cadssl'); ?></li>
                    <li><?php _e('wp-config.php: 600', 'cadssl'); ?></li>
                </ul>
                
                <form method="post" action="">
                    <?php wp_nonce_field('cadssl_file_permissions_scan'); ?>
                    <p>
                        <input type="submit" name="cadssl_run_scan" class="button button-primary" value="<?php _e('Run Permissions Scan', 'cadssl'); ?>">
                        <?php 
                        $last_scan_time = get_option('cadssl_last_permissions_scan_time');
                        if ($last_scan_time) {
                            printf(
                                __('Last scan: %s', 'cadssl'),
                                date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($last_scan_time))
                            );
                        }
                        ?>
                    </p>
                </form>
            </div>
            
            <div id="cadssl-scan-messages"></div>
            
            <?php if ($scan_results): ?>
                <h2><?php _e('Scan Results', 'cadssl'); ?></h2>
                
                <?php if (empty($scan_results['issues'])): ?>
                    <div class="notice notice-success">
                        <p><?php _e('All scanned files and directories have appropriate permissions!', 'cadssl'); ?></p>
                    </div>
                <?php else: ?>
                    <div class="notice notice-warning">
                        <p>
                            <?php 
                            printf(
                                __('Found %d files or directories with insecure permissions. These should be fixed for better security.', 'cadssl'),
                                count($scan_results['issues'])
                            ); 
                            ?>
                        </p>
                    </div>
                    
                    <form method="post" action="" id="cadssl-fix-permissions-form">
                        <?php wp_nonce_field('cadssl_fix_permissions'); ?>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th class="check-column"><input type="checkbox" id="select-all-files"></th>
                                    <th><?php _e('Path', 'cadssl'); ?></th>
                                    <th><?php _e('Type', 'cadssl'); ?></th>
                                    <th><?php _e('Current Permissions', 'cadssl'); ?></th>
                                    <th><?php _e('Recommended', 'cadssl'); ?></th>
                                    <th><?php _e('Owner', 'cadssl'); ?></th>
                                    <th><?php _e('Risk Level', 'cadssl'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($scan_results['issues'] as $issue): ?>
                                <tr>
                                    <td>
                                        <input type="checkbox" name="fix_files[]" value="<?php echo esc_attr(json_encode(array(
                                            'path' => $issue['path'],
                                            'recommended' => $issue['recommended']
                                        ))); ?>" class="file-checkbox">
                                    </td>
                                    <td><?php echo esc_html($issue['path']); ?></td>
                                    <td><?php echo esc_html($issue['type']); ?></td>
                                    <td><?php echo esc_html($issue['current']); ?></td>
                                    <td><?php echo esc_html($issue['recommended']); ?></td>
                                    <td><?php echo esc_html($issue['owner']); ?></td>
                                    <td>
                                        <?php
                                        $risk_class = '';
                                        switch ($issue['risk']) {
                                            case 'high': 
                                                $risk_class = 'cadssl-issue-critical'; 
                                                break;
                                            case 'medium': 
                                                $risk_class = 'cadssl-issue-warning'; 
                                                break;
                                            case 'low': 
                                                $risk_class = ''; 
                                                break;
                                        }
                                        ?>
                                        <span class="<?php echo esc_attr($risk_class); ?>">
                                            <?php echo esc_html(ucfirst($issue['risk'])); ?>
                                        </span>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                        
                        <p>
                            <button type="button" class="button" id="select-all"><?php _e('Select All', 'cadssl'); ?></button>
                            <button type="button" class="button" id="deselect-all"><?php _e('Deselect All', 'cadssl'); ?></button>
                            <button type="submit" id="cadssl-fix-permissions-btn" class="button button-primary"><?php _e('Fix Selected Files', 'cadssl'); ?></button>
                            <span class="spinner cadssl-save-indicator"></span>
                        </p>
                        
                        <div class="notice notice-warning inline">
                            <p>
                                <strong><?php _e('Warning:', 'cadssl'); ?></strong> 
                                <?php _e('Changing file permissions may affect how your site functions. In some shared hosting environments, you might not have permission to change file ownership.', 'cadssl'); ?>
                            </p>
                        </div>
                    </form>
                <?php endif; ?>
            <?php endif; ?>
        </div>
        <?php
    }
    
    /**
     * Scan file permissions
     * 
     * @return array Scan results
     */
    public function scan_file_permissions() {
        $results = array(
            'issues' => array(),
            'secure' => array(),
        );
        
        // Get WordPress root directory
        $wp_root = ABSPATH;
        
        // Check critical files
        $this->check_file_permissions($wp_root . 'wp-config.php', '0600', $results);
        $this->check_file_permissions($wp_root . '.htaccess', '0644', $results);
        $this->check_file_permissions($wp_root . 'index.php', '0644', $results);
        
        // Check wp-content directory
        $this->check_directory_permissions($wp_root . 'wp-content', '0755', $results);
        
        // Check uploads directory
        $this->check_directory_permissions($wp_root . 'wp-content/uploads', '0755', $results);
        
        // Check plugins directory
        $this->check_directory_permissions($wp_root . 'wp-content/plugins', '0755', $results);
        
        // Check themes directory
        $this->check_directory_permissions($wp_root . 'wp-content/themes', '0755', $results);
        
        // Check wp-includes directory - should be read-only
        $this->check_directory_permissions($wp_root . 'wp-includes', '0755', $results, false, true);
        
        return $results;
    }
    
    /**
     * Check file permissions
     * 
     * @param string $file File path
     * @param string $recommended Recommended permissions
     * @param array &$results Results array to populate
     */
    private function check_file_permissions($file, $recommended, &$results) {
        if (!file_exists($file)) {
            return;
        }
        
        $perms = $this->get_permissions($file);
        $owner = $this->get_file_owner($file);
        $risk = $this->assess_permissions_risk($perms, $recommended, false);
        
        if ($this->is_secure_permissions($perms, $recommended, false)) {
            $results['secure'][] = array(
                'path' => $this->get_relative_path($file),
                'type' => 'file',
                'current' => $perms,
                'recommended' => $recommended,
                'owner' => $owner,
                'risk' => $risk
            );
        } else {
            $results['issues'][] = array(
                'path' => $this->get_relative_path($file),
                'type' => 'file',
                'current' => $perms,
                'recommended' => $recommended,
                'owner' => $owner,
                'risk' => $risk
            );
        }
    }
    
    /**
     * Check directory permissions
     * 
     * @param string $dir Directory path
     * @param string $recommended Recommended permissions
     * @param array &$results Results array to populate
     * @param bool $recursive Whether to check recursively
     * @param bool $read_only Whether directory should be read-only
     */
    private function check_directory_permissions($dir, $recommended, &$results, $recursive = false, $read_only = false) {
        if (!is_dir($dir)) {
            return;
        }
        
        $perms = $this->get_permissions($dir);
        $owner = $this->get_file_owner($dir);
        $risk = $this->assess_permissions_risk($perms, $recommended, true);
        
        if ($this->is_secure_permissions($perms, $recommended, true)) {
            $results['secure'][] = array(
                'path' => $this->get_relative_path($dir),
                'type' => 'directory',
                'current' => $perms,
                'recommended' => $recommended,
                'owner' => $owner,
                'risk' => $risk
            );
        } else {
            $results['issues'][] = array(
                'path' => $this->get_relative_path($dir),
                'type' => 'directory',
                'current' => $perms,
                'recommended' => $recommended,
                'owner' => $owner,
                'risk' => $risk
            );
        }
        
        // Check recursively if required
        if ($recursive) {
            $files = scandir($dir);
            foreach ($files as $file) {
                if ($file === '.' || $file === '..') {
                    continue;
                }
                
                $path = $dir . '/' . $file;
                
                if (is_dir($path)) {
                    $this->check_directory_permissions($path, $recommended, $results, $recursive, $read_only);
                } elseif (is_file($path)) {
                    // For files within the directory, use 0644 (read-write for owner, read for others)
                    $file_recommended = $read_only ? '0444' : '0644';
                    $this->check_file_permissions($path, $file_recommended, $results);
                }
            }
        }
    }
    
    /**
     * Get file permissions in octal format
     * 
     * @param string $file File path
     * @return string Permissions in octal format
     */
    private function get_permissions($file) {
        return substr(sprintf('%o', fileperms($file)), -4);
    }
    
    /**
     * Get file or directory owner
     * 
     * @param string $file File path
     * @return string Owner name or UID
     */
    private function get_file_owner($file) {
        $owner = fileowner($file);
        if (function_exists('posix_getpwuid')) {
            $owner_info = posix_getpwuid($owner);
            return $owner_info['name'];
        } else {
            return $owner;
        }
    }
    
    /**
     * Get relative path from WordPress root
     * 
     * @param string $file Full file path
     * @return string Relative path
     */
    private function get_relative_path($file) {
        return str_replace(ABSPATH, '', $file);
    }
    
    /**
     * Check if permissions are secure
     * 
     * @param string $current Current permissions
     * @param string $recommended Recommended permissions
     * @param bool $is_dir Whether the path is a directory
     * @return bool True if permissions are secure
     */
    private function is_secure_permissions($current, $recommended, $is_dir) {
        // Convert to decimal for comparison
        $current_dec = octdec($current);
        $recommended_dec = octdec($recommended);
        
        if ($is_dir) {
            // For directories, check if world-writable
            return !($current_dec & 0002);
        } else {
            // For files, check against recommended permissions
            // Allow more restrictive permissions
            return $current_dec <= $recommended_dec;
        }
    }
    
    /**
     * Assess risk level of permissions
     * 
     * @param string $current Current permissions
     * @param string $recommended Recommended permissions
     * @param bool $is_dir Whether the path is a directory
     * @return string Risk level: high, medium, low
     */
    private function assess_permissions_risk($current, $recommended, $is_dir) {
        $current_dec = octdec($current);
        
        // World-writable is always high risk
        if ($current_dec & 0002) {
            return 'high';
        }
        
        // Group-writable is medium risk
        if ($current_dec & 0020) {
            return 'medium';
        }
        
        // For critical files, any deviation is medium risk
        if (!$is_dir && $current !== $recommended && $recommended === '0600') {
            return 'medium';
        }
        
        // Other deviations are low risk
        if ($current !== $recommended) {
            return 'low';
        }
        
        return 'low';
    }
    
    /**
     * Run automated permissions scan
     */
    public function run_automated_scan() {
        $results = $this->scan_file_permissions();
        update_option('cadssl_last_permissions_scan', $results);
        update_option('cadssl_last_permissions_scan_time', date('Y-m-d H:i:s'));
        
        // Check if there are any high-risk permission issues
        $high_risk_issues = 0;
        foreach ($results['issues'] as $issue) {
            if ($issue['risk'] === 'high') {
                $high_risk_issues++;
            }
        }
        
        // Send email notification if there are high-risk issues
        if ($high_risk_issues > 0) {
            $options = get_option('cadssl_options');
            if (isset($options['permissions_scan_notify']) && $options['permissions_scan_notify']) {
                $admin_email = get_option('admin_email');
                $site_url = get_site_url();
                $subject = sprintf(__('File Permission Issues Detected: %s', 'cadssl'), parse_url($site_url, PHP_URL_HOST));
                
                $message = sprintf(
                    __('The automated file permissions scan for your WordPress site %1$s has detected %2$d high-risk file permission issues that need your attention. Please login to your WordPress admin panel and check the File Permissions scanner results.', 'cadssl'),
                    $site_url,
                    $high_risk_issues
                );
                
                $headers = array('Content-Type: text/html; charset=UTF-8');
                
                wp_mail($admin_email, $subject, $message, $headers);
            }
        }
    }
    
    /**
     * Fix file permissions
     * 
     * @param array $files Files to fix
     * @return array Results
     */
    public function fix_file_permissions($files) {
        $results = array(
            'fixed' => 0,
            'failed' => 0,
            'details' => array()
        );
        
        foreach ($files as $file_json) {
            $file_data = json_decode(stripslashes($file_json), true);
            if (!isset($file_data['path']) || !isset($file_data['recommended'])) {
                $results['failed']++;
                continue;
            }
            
            $path = ABSPATH . $file_data['path'];
            $recommended = $file_data['recommended'];
            
            if (!file_exists($path)) {
                $results['failed']++;
                $results['details'][] = sprintf(__('Failed: %s - File not found', 'cadssl'), $file_data['path']);
                continue;
            }
            
            $chmod_result = @chmod($path, octdec($recommended));
            
            if ($chmod_result) {
                $results['fixed']++;
                $results['details'][] = sprintf(__('Fixed: %s - Changed permissions to %s', 'cadssl'), $file_data['path'], $recommended);
            } else {
                $results['failed']++;
                $results['details'][] = sprintf(__('Failed: %s - Could not change permissions', 'cadssl'), $file_data['path']);
            }
        }
        
        return $results;
    }
    
    /**
     * AJAX handler for fixing permissions
     */
    public function ajax_fix_permissions() {
        // Verify nonce
        check_ajax_referer('cadssl_fix_permissions', 'security');
        
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You do not have permission to perform this action.', 'cadssl')));
        }
        
        // Get files to fix
        $files = isset($_POST['files']) ? $_POST['files'] : array();
        
        // Fix file permissions
        $results = $this->fix_file_permissions($files);
        
        // Send response
        if ($results['failed'] > 0) {
            wp_send_json_error(array('message' => __('Some files could not be fixed.', 'cadssl'), 'results' => $results));
        } else {
            wp_send_json_success(array('message' => __('All files were fixed successfully.', 'cadssl'), 'results' => $results));
        }
    }
}