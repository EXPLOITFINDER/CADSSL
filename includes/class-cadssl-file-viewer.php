<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * File Viewer for inspecting suspicious code
 */
class CADSSL_File_Viewer {
    /**
     * Initialize file viewer
     */
    public function init() {
        // Add admin menu
        add_action('admin_menu', array($this, 'add_file_viewer_menu'), 90);
        
        // Register styles and scripts
        add_action('admin_enqueue_scripts', array($this, 'enqueue_assets'));
    }
    
    /**
     * Add file viewer submenu (hidden from menu)
     */
    public function add_file_viewer_menu() {
        // Add as hidden page (not showing in menu)
        add_submenu_page(
            null, // No parent menu
            __('File Viewer', 'cadssl'),
            __('File Viewer', 'cadssl'),
            'manage_options',
            'cadssl-file-viewer',
            array($this, 'display_file_viewer_page')
        );
    }
    
    /**
     * Enqueue assets for file viewer
     * 
     * @param string $hook Current admin page
     */
    public function enqueue_assets($hook) {
        if ('admin_page_cadssl-file-viewer' !== $hook) {
            return;
        }
        
        // Prism syntax highlighter
        wp_enqueue_style('cadssl-prism-css', CADSSL_URL . 'assets/css/prism.css', array(), CADSSL_VERSION);
        wp_enqueue_script('cadssl-prism-js', CADSSL_URL . 'assets/js/prism.js', array(), CADSSL_VERSION, true);
        
        // Custom styles
        wp_add_inline_style('cadssl-prism-css', '
            .file-viewer-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
                padding: 10px;
                background-color: #f8f9fa;
                border: 1px solid #e2e4e7;
            }
            .file-info {
                flex: 1;
            }
            .file-info p {
                margin: 5px 0;
            }
            .file-actions {
                text-align: right;
            }
            .file-viewer-content {
                position: relative;
                border: 1px solid #e2e4e7;
                max-height: 60vh;
                overflow: auto;
            }
            .line-numbers {
                position: absolute;
                left: 0;
                top: 0;
                width: 40px;
                background-color: #f8f9fa;
                text-align: right;
                padding: 10px 0;
                border-right: 1px solid #e2e4e7;
            }
            .line-number {
                padding: 0 5px;
                color: #999;
                font-size: 12px;
                line-height: 1.5em;
            }
            .highlight-line {
                background-color: #ffffcc;
            }
            .code-content {
                padding: 10px;
                padding-left: 50px;
                font-family: monospace;
                white-space: pre;
                line-height: 1.5em;
            }
            .infection-warning {
                margin: 15px 0;
                padding: 10px 15px;
                background-color: #f8d7da;
                border-left: 4px solid #dc3545;
                color: #721c24;
            }
        ');
    }
    
    /**
     * Display file viewer page
     */
    public function display_file_viewer_page() {
        // Verify user permissions
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'cadssl'));
        }
        
        // Get file path from URL
        $file_path = isset($_GET['file']) ? sanitize_text_field($_GET['file']) : '';
        $highlight_line = isset($_GET['line']) ? intval($_GET['line']) : 0;
        
        // Security check - ensure file is within WordPress directory
        $wp_root = ABSPATH;
        $full_path = $wp_root . ltrim($file_path, '/');
        $real_path = realpath($full_path);
        
        if (!$file_path || !$real_path || strpos($real_path, $wp_root) !== 0) {
            wp_die(__('Invalid file path.', 'cadssl'));
        }
        
        // File info
        $file_size = size_format(filesize($real_path));
        $file_modified = date_i18n(get_option('date_format') . ' ' . get_option('time_format'), filemtime($real_path));
        $file_type = wp_check_filetype($real_path)['type'];
        $file_perms = substr(sprintf('%o', fileperms($real_path)), -4);
        
        // Read file content
        $content = file_get_contents($real_path);
        $content = htmlspecialchars($content);
        $lines = explode("\n", $content);
        $total_lines = count($lines);
        
        ?>
        <div class="wrap">
            <h1><?php _e('File Viewer', 'cadssl'); ?></h1>
            
            <div class="infection-warning">
                <p><strong><?php _e('Warning:', 'cadssl'); ?></strong> <?php _e('This file has been flagged as potentially malicious. Review the code carefully and take appropriate action.', 'cadssl'); ?></p>
                <p><?php _e('If you recognize this file as legitimate, you can ignore this warning. If it appears to be malicious, you should take immediate action.', 'cadssl'); ?></p>
            </div>
            
            <div class="file-viewer-header">
                <div class="file-info">
                    <h2><?php echo esc_html(basename($file_path)); ?></h2>
                    <p>
                        <?php echo esc_html($file_path); ?><br>
                        <?php printf(__('Size: %s | Last Modified: %s | Permissions: %s', 'cadssl'), $file_size, $file_modified, $file_perms); ?>
                    </p>
                </div>
                <div class="file-actions">
                    <a href="<?php echo esc_url(admin_url('admin.php?page=cadssl-malware-scanner')); ?>" class="button"><?php _e('Back to Scanner', 'cadssl'); ?></a>
                    
                    <?php if (wp_is_writable($real_path)): ?>
                    <a href="#" class="button button-danger" id="quarantine-file"><?php _e('Quarantine File', 'cadssl'); ?></a>
                    <?php endif; ?>
                </div>
            </div>
            
            <div class="file-viewer-content">
                <div class="line-numbers">
                    <?php for ($i = 1; $i <= $total_lines; $i++): ?>
                        <div class="line-number <?php echo ($highlight_line == $i) ? 'highlight-line' : ''; ?>"><?php echo $i; ?></div>
                    <?php endfor; ?>
                </div>
                
                <pre class="code-content"><code class="language-php"><?php echo $content; ?></code></pre>
            </div>
            
            <div class="card" style="margin-top: 20px;">
                <h3><?php _e('What to do with suspicious files', 'cadssl'); ?></h3>
                <ol>
                    <li><?php _e('Examine the code carefully for malicious behavior like base64 encoded strings, eval() calls, etc.', 'cadssl'); ?></li>
                    <li><?php _e('If you recognize the file as part of a legitimate plugin or theme, it may be a false positive.', 'cadssl'); ?></li>
                    <li><?php _e('For unknown or suspicious files, consider removing or quarantining them.', 'cadssl'); ?></li>
                    <li><?php _e('After addressing the issue, scan your site again to ensure no other malicious files remain.', 'cadssl'); ?></li>
                </ol>
            </div>
            
            <script>
                document.addEventListener('DOMContentLoaded', function() {
                    // Scroll to highlighted line
                    const highlightedLine = document.querySelector('.highlight-line');
                    if (highlightedLine) {
                        highlightedLine.scrollIntoView({ block: 'center' });
                    }
                    
                    // Handle quarantine file action
                    document.getElementById('quarantine-file').addEventListener('click', function(e) {
                        e.preventDefault();
                        if (confirm('<?php _e("Are you sure you want to quarantine this file? The file will be renamed and made inaccessible. This action cannot be undone.", "cadssl"); ?>')) {
                            // TODO: Implement quarantine via AJAX
                            alert('<?php _e("Quarantine functionality will be implemented in the next version.", "cadssl"); ?>');
                        }
                    });
                });
            </script>
        </div>
        <?php
    }
    
    /**
     * Quarantine a suspicious file
     * 
     * @param string $file_path Path to the file
     * @return bool|WP_Error True on success, WP_Error on failure
     */
    public function quarantine_file($file_path) {
        // Security check - ensure file is within WordPress directory
        $wp_root = ABSPATH;
        $full_path = $wp_root . ltrim($file_path, '/');
        $real_path = realpath($full_path);
        
        if (!$file_path || !$real_path || strpos($real_path, $wp_root) !== 0) {
            return new WP_Error('invalid_path', __('Invalid file path.', 'cadssl'));
        }
        
        // Create quarantine directory if it doesn't exist
        $quarantine_dir = CADSSL_PATH . 'quarantine';
        if (!file_exists($quarantine_dir)) {
            wp_mkdir_p($quarantine_dir);
            
            // Protect directory with .htaccess
            $htaccess = $quarantine_dir . '/.htaccess';
            file_put_contents($htaccess, "Order deny,allow\nDeny from all");
            
            // Add empty index.php file
            file_put_contents($quarantine_dir . '/index.php', "<?php\n// Silence is golden.");
        }
        
        // Generate unique filename for the quarantined file
        $filename = basename($real_path);
        $quarantined_file = $quarantine_dir . '/' . $filename . '.' . time() . '.quarantine';
        
        // Move file to quarantine
        if (@rename($real_path, $quarantined_file)) {
            // Log the quarantine action
            $this->log_quarantine_action($file_path, $quarantined_file);
            return true;
        }
        
        return new WP_Error('quarantine_failed', __('Failed to quarantine the file.', 'cadssl'));
    }
    
    /**
     * Log quarantine action
     * 
     * @param string $original_path Original file path
     * @param string $quarantined_path Path to quarantined file
     */
    private function log_quarantine_action($original_path, $quarantined_path) {
        $log = get_option('cadssl_quarantine_log', array());
        
        $log[] = array(
            'original_path' => $original_path,
            'quarantined_path' => $quarantined_path,
            'timestamp' => time(),
            'user' => get_current_user_id()
        );
        
        update_option('cadssl_quarantine_log', $log);
    }
}
