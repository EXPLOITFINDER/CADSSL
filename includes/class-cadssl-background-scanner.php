<?php
/**
 * Background Scanner class
 * Handles scanning files in the background using WP Cron
 */
class CADSSL_Background_Scanner {
    /**
     * Number of files to process per batch
     */
    const BATCH_SIZE = 10;
    
    /**
     * Initialize the background scanner
     */
    public function init() {
        // Register cron action
        add_action('cadssl_background_scan_batch', array($this, 'process_scan_batch'), 10, 2);
        
        // Add AJAX handlers
        add_action('wp_ajax_cadssl_start_background_scan', array($this, 'ajax_start_background_scan'));
        add_action('wp_ajax_cadssl_get_background_scan_status', array($this, 'ajax_get_scan_status'));
        add_action('wp_ajax_cadssl_stop_background_scan', array($this, 'ajax_stop_background_scan'));
        
        // Add new handler to force release locks
        add_action('wp_ajax_cadssl_force_release_scan_lock', array($this, 'ajax_force_release_scan_lock'));
        
        // Add direct processing endpoint
        add_action('wp_ajax_cadssl_direct_process_batch', array($this, 'ajax_direct_process_batch'));
    }
    
    /**
     * AJAX: Start background scan
     */
    public function ajax_start_background_scan() {
        check_ajax_referer('cadssl_start_background_scan', 'security');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You do not have permission to perform this action.', 'cadssl')));
            return;
        }
        
        // Check if a scan is already running
        $lock = new CADSSL_Process_Lock('malware_scan', 3600); // 1 hour lock
        if ($lock->is_locked()) {
            $lock_info = $lock->get_lock_info();
            $formatted_time = get_date_from_gmt(date('Y-m-d H:i:s', $lock_info['time']), get_option('date_format') . ' ' . get_option('time_format'));
            
            wp_send_json_error(array(
                'message' => sprintf(__('A scan is already in progress (started at %s). Please wait for it to complete or force release the lock.', 'cadssl'), $formatted_time),
                'lock_info' => $lock->get_lock_info()
            ));
            return;
        }
        
        // Get scanner instance
        $scanner = new CADSSL_Malware_Scanner();
        
        try {
            // Acquire lock for this process
            $lock->acquire();
            
            // Get files to scan - with better error handling
            try {
                // Use the wrapper method instead of trying to access private method
                $files_to_scan = $this->get_files_to_scan_wrapper();
                
                if (empty($files_to_scan)) {
                    $lock->release();
                    wp_send_json_error(array('message' => __('No files found to scan.', 'cadssl')));
                    return;
                }
                
                // Ensure the count is reasonable
                if (count($files_to_scan) > 50000) {
                    // Trim list to prevent performance issues
                    $files_to_scan = array_slice($files_to_scan, 0, 50000);
                }
            } catch (Exception $e) {
                $lock->release();
                wp_send_json_error(array('message' => __('Error preparing file list: ', 'cadssl') . $e->getMessage()));
                return;
            }
            
            // Create scan data with enhanced meta information
            $scan_id = uniqid('scan_');
            $scan_data = array(
                'id' => $scan_id,
                'total_files' => count($files_to_scan),
                'scanned_files' => 0,
                'files' => $files_to_scan,
                'issues' => array(),
                'start_time' => time(),
                'status' => 'starting',
                'last_active' => time(),
                'current_file' => '',
                'errors' => array(),
                'server_info' => array(
                    'php_version' => phpversion(),
                    'memory_limit' => ini_get('memory_limit'),
                    'max_execution_time' => ini_get('max_execution_time')
                ),
                'user_id' => get_current_user_id()
            );
            
            // Save scan data
            update_option('cadssl_background_scan_' . $scan_id, $scan_data);
            
            // Record the active scan ID in a dedicated option for easy lookup
            update_option('cadssl_active_background_scan', $scan_id);
            
            // Make sure cron is working
            if (defined('DISABLE_WP_CRON') && DISABLE_WP_CRON) {
                // Log warning when WP Cron is disabled
                $scan_data['warnings'] = array(__('WP Cron is disabled on this site. You may need to trigger cron manually for background scanning to work.', 'cadssl'));
                update_option('cadssl_background_scan_' . $scan_id, $scan_data);
            }
            
            // Schedule the first batch with immediate execution
            wp_schedule_single_event(time(), 'cadssl_background_scan_batch', array($scan_id, 0));
            
            // Spawn a loopback request to ensure the cron runs immediately
            $this->spawn_cron();
            
            // Also run a backup direct trigger for environments with unreliable cron
            $this->direct_trigger_batch($scan_id, 0);
            
            wp_send_json_success(array(
                'scan_id' => $scan_id,
                'total_files' => count($files_to_scan),
                'message' => __('Background scan started successfully.', 'cadssl')
            ));
            
        } catch (Exception $e) {
            // Release lock on error
            $lock->release();
            
            wp_send_json_error(array(
                'message' => $e->getMessage(),
                'error' => true
            ));
        }
    }
    
    /**
     * Direct trigger batch processing (backup mechanism for unreliable cron)
     * 
     * @param string $scan_id
     * @param int $offset
     */
    private function direct_trigger_batch($scan_id, $offset) {
        // Make a non-blocking request to process first batch
        $admin_url = admin_url('admin-ajax.php');
        $args = array(
            'timeout' => 0.01, // Basically fire and forget
            'blocking' => false,
            'body' => array(
                'action' => 'cadssl_direct_process_batch',
                'security' => wp_create_nonce('cadssl_direct_process_batch'),
                'scan_id' => $scan_id,
                'offset' => $offset
            )
        );
        
        wp_remote_post($admin_url, $args);
    }
    
    /**
     * Direct AJAX batch processing (backup for when cron doesn't work)
     */
    public function ajax_direct_process_batch() {
        check_ajax_referer('cadssl_direct_process_batch', 'security');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error();
            return;
        }
        
        $scan_id = isset($_POST['scan_id']) ? sanitize_text_field($_POST['scan_id']) : '';
        $offset = isset($_POST['offset']) ? intval($_POST['offset']) : 0;
        
        if (empty($scan_id)) {
            wp_send_json_error();
            return;
        }
        
        // Note: we're not waiting for this to complete
        $this->process_scan_batch($scan_id, $offset);
        
        // Send quick response and end
        wp_send_json_success();
        exit;
    }
    
    /**
     * AJAX: Get scan status
     * Modified to use the progress tracker for more consistent results
     */
    public function ajax_get_scan_status() {
        check_ajax_referer('cadssl_background_scan_status', 'security');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You do not have permission to perform this action.', 'cadssl')));
            return;
        }
        
        // Get scan ID
        $scan_id = isset($_POST['scan_id']) ? sanitize_text_field($_POST['scan_id']) : '';
        
        if (empty($scan_id)) {
            wp_send_json_error(array('message' => __('Invalid scan ID.', 'cadssl')));
            return;
        }
        
        // Check for force update
        $force_update = isset($_POST['force_update']) && (int)$_POST['force_update'] === 1;
        
        // First try to get progress from the progress tracker for more reliable status
        $progress_data = null;
        if (class_exists('CADSSL_Progress_Tracker')) {
            $progress_data = CADSSL_Progress_Tracker::get_progress($scan_id);
        }
        
        // If no progress data, fall back to the database option
        if (!$progress_data) {
            $scan_data = get_option('cadssl_background_scan_' . $scan_id);
            
            if (!$scan_data) {
                wp_send_json_error(array('message' => __('Scan data not found.', 'cadssl')));
                return;
            }
            
            // Check if scan is active (last activity within 60 seconds)
            $is_active = (time() - $scan_data['last_active']) < 60;
            
            // Calculate progress
            $progress = 0;
            if ($scan_data['total_files'] > 0) {
                $progress = round(($scan_data['scanned_files'] / $scan_data['total_files']) * 100, 1);
            }
        } else {
            // Use the progress tracker data
            $scan_data = $progress_data;
            $is_active = $progress_data['is_active'];
            $progress = $progress_data['progress_percent'];
        }
        
        // Check if scan is complete
        $is_complete = $scan_data['status'] === 'completed';
        
        // If scan is stalled (inactive for over 5 minutes but not completed/stopped), try to restart it
        if ((!$is_active && !in_array($scan_data['status'], array('completed', 'stopped')) && 
            (time() - $scan_data['last_active'] > 300)) || $force_update) {
            
            // Attempt to restart the scan or get fresh status
            $scan_data['status'] = 'restarting';
            $scan_data['last_active'] = time();
            
            // Save updates to both databases
            if (!isset($scan_data['warnings'])) {
                $scan_data['warnings'] = array();
            }
            
            $scan_data['warnings'][] = __('Scan appears to be stalled. Attempting to restart.', 'cadssl');
            update_option('cadssl_background_scan_' . $scan_id, $scan_data);
            
            if (class_exists('CADSSL_Progress_Tracker')) {
                CADSSL_Progress_Tracker::update_progress($scan_id, $scan_data);
            }
            
            // Schedule batch with next offset
            wp_schedule_single_event(time(), 'cadssl_background_scan_batch', array(
                $scan_id, $scan_data['scanned_files']
            ));
            
            // Spawn cron
            $this->spawn_cron();
            
            // Also use direct trigger as backup
            $this->direct_trigger_batch($scan_id, $scan_data['scanned_files']);
        }
        
        // Get current file being scanned
        $current_file = !empty($scan_data['current_file']) ? 
            basename($scan_data['current_file']) : 
            '';
        
        // Get warnings - limited to last 5
        $warnings = isset($scan_data['warnings']) ? array_slice($scan_data['warnings'], -5) : array();
        
        // Prepare response
        $response = array(
            'scan_id' => $scan_id,
            'total_files' => $scan_data['total_files'],
            'scanned_files' => $scan_data['scanned_files'],
            'progress' => $progress,
            'is_active' => $is_active,
            'status' => $scan_data['status'],
            'current_file' => $current_file,
            'issues_count' => isset($scan_data['issues']) ? count($scan_data['issues']) : 0,
            'start_time' => $scan_data['start_time'],
            'last_active' => $scan_data['last_active'],
            'elapsed_time' => time() - $scan_data['start_time'],
            'has_errors' => !empty($scan_data['errors']),
            'warnings' => $warnings,
            'using_progress_tracker' => isset($progress_data)
        );
        
        // If scan is complete, include results
        if ($is_complete) {
            $response['results_url'] = admin_url('admin.php?page=cadssl-malware-scanner&view=results&scan_id=' . $scan_id);
        }
        
        wp_send_json_success($response);
    }
    
    /**
     * AJAX: Stop background scan
     */
    public function ajax_stop_background_scan() {
        check_ajax_referer('cadssl_stop_background_scan', 'security');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You do not have permission to perform this action.', 'cadssl')));
            return;
        }
        
        // Get scan ID
        $scan_id = isset($_POST['scan_id']) ? sanitize_text_field($_POST['scan_id']) : '';
        
        if (empty($scan_id)) {
            wp_send_json_error(array('message' => __('Invalid scan ID.', 'cadssl')));
            return;
        }
        
        // Get scan data
        $scan_data = get_option('cadssl_background_scan_' . $scan_id);
        
        if (!$scan_data) {
            wp_send_json_error(array('message' => __('Scan data not found.', 'cadssl')));
            return;
        }
        
        // Update status to stopped
        $scan_data['status'] = 'stopped';
        $scan_data['last_active'] = time();
        update_option('cadssl_background_scan_' . $scan_id, $scan_data);
        
        // Remove any scheduled batches
        wp_clear_scheduled_hook('cadssl_background_scan_batch', array($scan_id, 0));
        
        // Clear active scan reference
        delete_option('cadssl_active_background_scan');
        
        // Release lock
        $lock = new CADSSL_Process_Lock('malware_scan');
        $lock->release();
        
        wp_send_json_success(array(
            'message' => __('Scan stopped successfully.', 'cadssl')
        ));
    }
    
    /**
     * AJAX: Force release a potentially stuck scan lock
     */
    public function ajax_force_release_scan_lock() {
        check_ajax_referer('cadssl_force_release_lock', 'security');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You do not have permission to perform this action.', 'cadssl')));
            return;
        }
        
        $lock = new CADSSL_Process_Lock('malware_scan');
        $lock_info = $lock->get_lock_info();
        
        // Release the lock
        $lock->release();
        
        // Also clean up any active scan references
        delete_option('cadssl_active_background_scan');
        
        wp_send_json_success(array(
            'message' => __('Scan lock has been forcibly released.', 'cadssl'),
            'was_locked' => !empty($lock_info)
        ));
    }
    
    /**
     * Check if a scan lock exists and get its information
     * 
     * @return array|false Lock information or false if no lock
     */
    public function get_scan_lock_info() {
        $lock = new CADSSL_Process_Lock('malware_scan');
        return $lock->get_lock_info();
    }
    
    /**
     * Process a scan batch
     * 
     * @param string $scan_id Scan ID
     * @param int $offset Current offset
     */
    public function process_scan_batch($scan_id, $offset = 0) {
        // Get scan data
        $scan_data = get_option('cadssl_background_scan_' . $scan_id);
        
        if (!$scan_data) {
            // Scan data not found, nothing to do
            return;
        }
        
        // Check if scan is stopped
        if ($scan_data['status'] === 'stopped') {
            return;
        }
        
        // Update status to processing and log the batch start
        $scan_data['status'] = 'processing';
        $scan_data['last_active'] = time();
        $scan_data['current_batch'] = array(
            'offset' => $offset,
            'start_time' => time()
        );
        update_option('cadssl_background_scan_' . $scan_id, $scan_data);
        
        // Also update the progress tracker for improved consistency across page loads
        if (class_exists('CADSSL_Progress_Tracker')) {
            CADSSL_Progress_Tracker::update_progress($scan_id, [
                'scanned_files' => $scan_data['scanned_files'],
                'total_files' => $scan_data['total_files'],
                'status' => $scan_data['status'],
                'last_active' => $scan_data['last_active'],
                'current_file' => isset($scan_data['current_file']) ? $scan_data['current_file'] : '',
                'issues_count' => isset($scan_data['issues']) ? count($scan_data['issues']) : 0,
            ]);
        }
        
        try {
            // Get scanner instance and increase available resources
            $scanner = new CADSSL_Malware_Scanner();
            $this->increase_resources(); // Using a public method now instead of private
            
            // Get files for this batch - with smaller batch size for better reliability
            $batch_size = 3; // Even smaller batch size for better reliability and responsiveness
            $files = array_slice($scan_data['files'], $offset, $batch_size);
            
            if (empty($files)) {
                // No more files to scan, finalize
                $this->finalize_scan($scan_data);
                return;
            }
            
            // Scan batch of files
            $issues = array();
            $files_processed = 0;
            $skipped_files = 0;
            
            foreach ($files as $file) {
                try {
                    // Set a timeout for scanning each file
                    $start_time = microtime(true);
                    $max_time_per_file = 10; // 10 seconds max per file
                    
                    // Update current file and save progress frequently
                    $scan_data['current_file'] = $file;
                    $scan_data['last_active'] = time();
                    update_option('cadssl_background_scan_' . $scan_id, $scan_data);
                    
                    // Update progress tracker with current file
                    if (class_exists('CADSSL_Progress_Tracker')) {
                        CADSSL_Progress_Tracker::update_progress($scan_id, [
                            'scanned_files' => $scan_data['scanned_files'],
                            'total_files' => $scan_data['total_files'],
                            'status' => $scan_data['status'],
                            'last_active' => $scan_data['last_active'],
                            'current_file' => $file,
                            'issues_count' => isset($scan_data['issues']) ? count($scan_data['issues']) : 0,
                        ]);
                    }
                    
                    // Skip if file should be excluded
                    if ($scanner->is_excluded($file)) {
                        $files_processed++;
                        continue;
                    }
                    
                    // Skip scanning if file doesn't exist or is too big
                    if (!file_exists($file) || !is_readable($file) || filesize($file) > 5 * 1024 * 1024) {
                        $files_processed++;
                        continue;
                    }
                    
                    // Scan the file with a timeout
                    $file_issues = array();
                    
                    // Set up a custom error handler to catch timeouts
                    set_error_handler(function($severity, $message, $file, $line) {
                        throw new Exception($message);
                    });
                    
                    // Use a separate process or timeout mechanism for scanning files
                    $continue_scan = true;
                    while ($continue_scan && (microtime(true) - $start_time) < $max_time_per_file) {
                        // Scan the file with a small internal chunk to prevent timeouts
                        $result = $scanner->scan_file_safely($file);
                        if (!empty($result)) {
                            $file_issues = array_merge($file_issues, $result);
                        }
                        $continue_scan = false; // One pass is enough
                    }
                    
                    // Restore normal error handler
                    restore_error_handler();
                    
                    // If the file took too long to scan, log it and move on
                    if ((microtime(true) - $start_time) >= $max_time_per_file) {
                        $scan_data['warnings'][] = "File {$file} took too long to scan and was skipped.";
                        $skipped_files++;
                        $files_processed++; // Still count it as processed
                        continue;
                    }
                    
                    // Store results if issues found
                    if (!empty($file_issues)) {
                        $issues[$file] = $file_issues;
                    }
                    
                    $files_processed++;
                    
                    // Add a small delay between files to prevent server overload
                    usleep(50000); // 50ms
                    
                } catch (Exception $e) {
                    // Log error but continue
                    $scan_data['errors'][] = array(
                        'file' => $file,
                        'message' => $e->getMessage(),
                        'time' => time()
                    );
                    
                    // Limit errors to 100 to prevent huge data
                    if (count($scan_data['errors']) > 100) {
                        array_shift($scan_data['errors']);
                    }
                    
                    $files_processed++;
                    $skipped_files++;
                    
                    // Check if we should continue or abort this batch
                    if (count($scan_data['errors']) > 5) {
                        // Too many errors in this batch, schedule next batch and exit
                        break;
                    }
                }
            }
            
            // Update scan data
            $scan_data['scanned_files'] += $files_processed;
            $scan_data['issues'] = array_merge($scan_data['issues'], $issues);
            $scan_data['last_active'] = time();
            $scan_data['current_batch']['end_time'] = time();
            $scan_data['current_batch']['files_processed'] = $files_processed;
            $scan_data['current_batch']['skipped_files'] = $skipped_files;
            
            update_option('cadssl_background_scan_' . $scan_id, $scan_data);
            
            // Update progress tracker with latest data
            if (class_exists('CADSSL_Progress_Tracker')) {
                CADSSL_Progress_Tracker::update_progress($scan_id, [
                    'scanned_files' => $scan_data['scanned_files'],
                    'total_files' => $scan_data['total_files'],
                    'status' => $scan_data['status'],
                    'last_active' => time(),
                    'current_file' => isset($scan_data['current_file']) ? $scan_data['current_file'] : '',
                    'issues_count' => isset($scan_data['issues']) ? count($scan_data['issues']) : 0,
                    'current_batch' => $offset + $files_processed,
                    'files_processed' => $files_processed,
                    'skipped_files' => $skipped_files
                ]);
            }
            
            // Calculate next offset
            $next_offset = $offset + $files_processed;
            
            // Schedule next batch with minimal delay
            wp_schedule_single_event(time(), 'cadssl_background_scan_batch', array(
                $scan_id, $next_offset
            ));
            
            // Also trigger direct processing as backup
            $this->direct_trigger_batch($scan_id, $next_offset);
            
        } catch (Exception $e) {
            // Log fatal error
            $scan_data['errors'][] = array(
                'file' => 'batch_processor',
                'message' => $e->getMessage(),
                'time' => time()
            );
            
            $scan_data['status'] = 'error';
            $scan_data['last_active'] = time();
            
            update_option('cadssl_background_scan_' . $scan_id, $scan_data);
            
            // Update progress tracker with error status
            if (class_exists('CADSSL_Progress_Tracker')) {
                CADSSL_Progress_Tracker::update_progress($scan_id, [
                    'scanned_files' => $scan_data['scanned_files'],
                    'total_files' => $scan_data['total_files'],
                    'status' => 'error',
                    'last_active' => time(),
                    'error_message' => $e->getMessage()
                ]);
            }
            
            // Release lock if we have a fatal error
            $lock = new CADSSL_Process_Lock('malware_scan');
            $lock->release();
        }
    }
    
    /**
     * Finalize scan
     * 
     * @param array $scan_data Scan data
     */
    public function finalize_scan($scan_data) {
        // Update scan status
        $scan_data['status'] = 'completed';
        $scan_data['last_active'] = time();
        
        // Save final scan data
        update_option('cadssl_background_scan_' . $scan_data['id'], $scan_data);
        
        // Update progress tracker with completed status
        if (class_exists('CADSSL_Progress_Tracker')) {
            CADSSL_Progress_Tracker::update_progress($scan_data['id'], [
                'scanned_files' => $scan_data['scanned_files'],
                'total_files' => $scan_data['total_files'],
                'status' => 'completed',
                'last_active' => time(),
                'issues_count' => isset($scan_data['issues']) ? count($scan_data['issues']) : 0,
                'completion_time' => time()
            ]);
        }
        
        // Create scan results for easy access
        $scan_results = array(
            'total_files' => $scan_data['total_files'],
            'issues' => $scan_data['issues'],
            'scan_time' => time() - $scan_data['start_time'],
            'completion_time' => time(),
            'scan_id' => $scan_data['id']
        );
        
        // Update last scan results
        update_option('cadssl_last_malware_scan_results', $scan_results);
        update_option('cadssl_last_malware_scan_time', date('Y-m-d H:i:s'));
    }
    
    /**
     * Increase server resources for scanning
     * Making this public to be accessible from process_scan_batch
     */
    public function increase_resources() {
        // Increase PHP memory limit
        if (function_exists('ini_set')) {
            @ini_set('memory_limit', '384M');
            @ini_set('max_execution_time', 300);
            @ini_set('display_errors', 0);
            @ini_set('log_errors', 1);
        }
        
        // Increase PHP time limit
        if (function_exists('set_time_limit') && !ini_get('safe_mode')) {
            @set_time_limit(300);
        }
        
        // Disable output buffering when not in AJAX context
        if (!defined('DOING_AJAX') || !DOING_AJAX) {
            @ob_end_clean();
        }
        
        // Ignore user aborts
        if (function_exists('ignore_user_abort')) {
            @ignore_user_abort(true);
        }
        
        // Prevent session timeouts
        if (session_id()) {
            @session_write_close();
        }
    }
    
    /**
     * Spawn a loopback request to trigger WP Cron
     */
    public function spawn_cron() {
        // Create a loopback request to make sure cron runs immediately
        $url = add_query_arg('doing_wp_cron', time(), site_url('wp-cron.php'));
        wp_remote_post($url, array(
            'timeout' => 0.01,
            'blocking' => false,
            'sslverify' => apply_filters('https_local_ssl_verify', false),
        ));
    }
    
    /**
     * Wrapper for getting files to scan
     * 
     * @return array List of files to scan
     */
    public function get_files_to_scan_wrapper() {
        $files = array();
        
        $exclude_patterns = array(
            '/wp-content/uploads/',
            '/wp-content/cache/',
            '/wp-content/backup/',
            '/wp-content/updraft/',
            '/wp-content/plugins/CADSSL/quarantine/'
        );
        
        $directory = ABSPATH;
        
        // Ensure directory exists
        if (!is_dir($directory)) {
            return $files;
        }
        
        $dir_iterator = new RecursiveDirectoryIterator($directory);
        $iterator = new RecursiveIteratorIterator($dir_iterator, RecursiveIteratorIterator::SELF_FIRST);
        
        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $file_path = $file->getPathname();
                
                // Skip if file is in excluded paths
                $excluded = false;
                foreach ($exclude_patterns as $pattern) {
                    if (strpos($file_path, $pattern) !== false) {
                        $excluded = true;
                        break;
                    }
                }
                
                if (!$excluded && $this->is_scannable_file($file_path)) {
                    $files[] = $file_path;
                }
            }
        }
        
        return $files;
    }
    
    /**
     * Check if file is scannable
     * 
     * @param string $file File path to check
     * @return bool True if file can be scanned
     */
    public function is_scannable_file($file) {
        // Get file extension
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        
        // List of extensions to scan
        $scan_extensions = array(
            'php', 'phtml', 'php4', 'php5', 'php7', 'phps',
            'js', 'html', 'htm', 'htaccess'
        );
        
        return in_array($extension, $scan_extensions);
    }
}
