<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * CADSSL Dashboard class
 * Handles the security dashboard and admin widgets
 */
class CADSSL_Dashboard {
    /**
     * Initialize dashboard functionality
     */
    public function init() {
        // Define plugin file constant if it doesn't exist
        if (!defined('CADSSL_FILE')) {
            define('CADSSL_FILE', plugin_dir_path(dirname(__FILE__)) . 'ssl.php');
        }
        
        // Add dashboard widget
        add_action('wp_dashboard_setup', array($this, 'add_dashboard_widget'));
        
        // Register dashboard page - use static property to prevent duplicates
        static $menu_registered = false;
        if (!$menu_registered) {
            add_action('admin_menu', array($this, 'add_dashboard_menu'), 10);
            $menu_registered = true;
        }
        
        // Add admin bar security status
        add_action('admin_bar_menu', array($this, 'add_admin_bar_security_status'), 100);
    }
    
    /**
     * Add dashboard menu
     */
    public function add_dashboard_menu() {
        // Use static property to track registered menus
        static $registered_menus = array();
        $menu_slug = 'cadssl-dashboard';
        
        // Only register if not already registered
        if (!isset($registered_menus[$menu_slug])) {
            add_submenu_page(
                'cadssl-settings',
                __('Security Dashboard', 'cadssl'),
                __('Dashboard', 'cadssl'),
                'manage_options',
                $menu_slug,
                array($this, 'display_dashboard_page')
            );
            
            $registered_menus[$menu_slug] = true;
        }
    }
    
    /**
     * Add dashboard widget
     */
    public function add_dashboard_widget() {
        wp_add_dashboard_widget(
            'cadssl_security_widget',
            __('CADSSL Security Status', 'cadssl'),
            array($this, 'display_dashboard_widget')
        );
    }
    
    /**
     * Display dashboard widget
     */
    public function display_dashboard_widget() {
        $security_status = $this->get_security_status();
        $score = $security_status['score'];
        $issues = $security_status['issues'];
        $total_issues = count($issues);
        
        // Determine status color
        $status_color = '#46b450'; // Green
        if ($score < 60) {
            $status_color = '#dc3232'; // Red
        } elseif ($score < 80) {
            $status_color = '#ffb900'; // Yellow
        }
        
        // Display security score
        ?>
        <style>
            .cadssl-security-score {
                position: relative;
                width: 100px;
                height: 100px;
                border-radius: 50%;
                background: #f0f0f1;
                margin: 0 auto 20px;
            }
            .cadssl-security-score-circle {
                position: absolute;
                top: 10px;
                left: 10px;
                width: 80px;
                height: 80px;
                border-radius: 50%;
                background: <?php echo $status_color; ?>;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-size: 24px;
                font-weight: bold;
            }
            .cadssl-security-issues {
                margin-top: 20px;
            }
            .cadssl-security-issues-list {
                max-height: 200px;
                overflow-y: auto;
                padding: 0 10px;
                border-left: 4px solid #e5e5e5;
            }
        </style>
        
        <div class="cadssl-security-score">
            <div class="cadssl-security-score-circle"><?php echo intval($score); ?></div>
        </div>
        
        <div class="cadssl-security-issues">
            <?php if ($total_issues > 0): ?>
                <p>
                    <?php printf(
                        _n(
                            'Found %d security issue that needs attention:', 
                            'Found %d security issues that need attention:', 
                            $total_issues, 
                            'cadssl'
                        ), 
                        $total_issues
                    ); ?>
                </p>
                <div class="cadssl-security-issues-list">
                    <ul>
                    <?php foreach($issues as $issue): ?>
                        <li>
                            <strong><?php echo esc_html($issue['title']); ?></strong>
                            <?php if (!empty($issue['action_url']) && !empty($issue['action_text'])): ?>
                                - <a href="<?php echo esc_url($issue['action_url']); ?>"><?php echo esc_html($issue['action_text']); ?></a>
                            <?php endif; ?>
                        </li>
                    <?php endforeach; ?>
                    </ul>
                </div>
            <?php else: ?>
                <p><?php _e('Great job! No security issues detected.', 'cadssl'); ?></p>
            <?php endif; ?>
        </div>
        
        <p class="cadssl-widget-footer">
            <a href="<?php echo admin_url('admin.php?page=cadssl-dashboard'); ?>"><?php _e('View Full Security Dashboard', 'cadssl'); ?></a>
        </p>
        <?php
    }
    
    /**
     * Display dashboard page
     */
    public function display_dashboard_page() {
        // Get security status
        $security_status = $this->get_security_status();
        $score = $security_status['score'];
        $issues = $security_status['issues'];
        $passed = $security_status['passed'];
        
        // Get latest scan times - use a consistent format for the dates
        $last_security_scan = get_option('cadssl_last_scan_time');
        $last_permissions_scan = get_option('cadssl_last_permissions_scan_time');
        $last_malware_scan = get_option('cadssl_last_malware_scan_time');
        
        // SSL status
        $ssl_checker = new CADSSL_SSL_Checker();
        $ssl_status = $ssl_checker->check_ssl_status();
        
        // Certificate info - fix the display for expired certificates
        $cert_info = false;
        $cert_expiration = get_option('cadssl_certificate_expiration');
        if ($cert_expiration && isset($cert_expiration['days_remaining'])) {
            $cert_info = $cert_expiration;
        }
        
        // Dashboard cards - use a flag to ensure each card type is only displayed once
        $displayed_cards = array(
            'ssl_status' => false,
            'security_scans' => false,
            'quick_actions' => false,
        );
        
        ?>
        <div class="wrap">
            <h1><?php _e('Security Dashboard', 'cadssl'); ?></h1>
            
            <!-- Dashboard header -->
            <div class="cadssl-dashboard-header">
                <div class="cadssl-dashboard-score-container">
                    <div class="cadssl-dashboard-score">
                        <div class="cadssl-dashboard-score-circle" style="
                            <?php if ($score < 60): ?>
                                background-color: #dc3232; /* Red */
                            <?php elseif ($score < 80): ?>
                                background-color: #ffb900; /* Yellow */
                            <?php else: ?>
                                background-color: #46b450; /* Green */
                            <?php endif; ?>
                        ">
                            <span><?php echo intval($score); ?></span>
                        </div>
                    </div>
                    <div class="cadssl-dashboard-score-label">
                        <?php _e('Security Score', 'cadssl'); ?>
                    </div>
                </div>
                
                <div class="cadssl-dashboard-summary">
                    <p>
                        <?php 
                        printf(
                            __('Your site has passed %d out of %d security checks.', 'cadssl'),
                            count($passed),
                            count($passed) + count($issues)
                        ); 
                        ?>
                    </p>
                    
                    <?php if (count($issues) > 0): ?>
                        <p>
                            <?php _e('Critical issues that need attention:', 'cadssl'); ?>
                        </p>
                        <ul>
                            <?php 
                            $critical_issues = array_filter($issues, function($issue) {
                                return $issue['status'] === 'critical';
                            });
                            
                            foreach ($critical_issues as $issue): ?>
                                <li>
                                    <?php echo esc_html($issue['title']); ?>
                                    <?php if (!empty($issue['action_url']) && !empty($issue['action_text'])): ?>
                                        - <a href="<?php echo esc_url($issue['action_url']); ?>"><?php echo esc_html($issue['action_text']); ?></a>
                                    <?php endif; ?>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                </div>
            </div>
            
            <div class="cadssl-dashboard-cards">
                <?php if (!$displayed_cards['ssl_status']): $displayed_cards['ssl_status'] = true; ?>
                <!-- SSL Status Card -->
                <div class="cadssl-dashboard-card">
                    <h2><?php _e('SSL Status', 'cadssl'); ?></h2>
                    <?php if ($ssl_status['is_ssl']): ?>
                        <div class="cadssl-dashboard-status-positive">
                            <span class="dashicons dashicons-yes"></span>
                            <?php _e('SSL is active', 'cadssl'); ?>
                        </div>
                    <?php else: ?>
                        <div class="cadssl-dashboard-status-negative">
                            <span class="dashicons dashicons-no"></span>
                            <?php _e('SSL is not active', 'cadssl'); ?>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($cert_info): ?>
                        <p>
                            <?php 
                            // Fix the display for expired certificates
                            if ($cert_info['days_remaining'] <= 0): ?>
                                <?php printf(
                                    __('Your SSL certificate expired on %s. Please renew it immediately.', 'cadssl'),
                                    date_i18n(get_option('date_format'), strtotime($cert_info['expires']))
                                ); ?>
                            <?php else: ?>
                                <?php printf(
                                    __('Your SSL certificate expires in %d days on %s.', 'cadssl'),
                                    $cert_info['days_remaining'],
                                    date_i18n(get_option('date_format'), strtotime($cert_info['expires']))
                                ); ?>
                            <?php endif; ?>
                        </p>
                    <?php endif; ?>
                    
                    <p class="cadssl-dashboard-card-actions">
                        <a href="<?php echo admin_url('admin.php?page=cadssl-ssl-status'); ?>" class="button">
                            <?php _e('View SSL Details', 'cadssl'); ?>
                        </a>
                    </p>
                </div>
                <?php endif; ?>
                
                <?php if (!$displayed_cards['security_scans']): $displayed_cards['security_scans'] = true; ?>
                <!-- Security Scans Card -->
                <div class="cadssl-dashboard-card">
                    <h2><?php _e('Security Scans', 'cadssl'); ?></h2>
                    <p>
                        <strong><?php _e('Last Security Scan:', 'cadssl'); ?></strong>
                        <?php 
                        if ($last_security_scan) {
                            echo date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($last_security_scan));
                        } else {
                            _e('Never', 'cadssl');
                        }
                        ?>
                    </p>
                    <p>
                        <strong><?php _e('Last File Permissions Scan:', 'cadssl'); ?></strong>
                        <?php 
                        if ($last_permissions_scan) {
                            echo date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($last_permissions_scan));
                        } else {
                            _e('Never', 'cadssl');
                        }
                        ?>
                    </p>
                    <p>
                        <strong><?php _e('Last Malware Scan:', 'cadssl'); ?></strong>
                        <?php 
                        if ($last_malware_scan) {
                            echo date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($last_malware_scan));
                        } else {
                            _e('Never', 'cadssl');
                        }
                        ?>
                    </p>
                    
                    <p class="cadssl-dashboard-card-actions">
                        <a href="<?php echo admin_url('admin.php?page=cadssl-security-scanner'); ?>" class="button">
                            <?php _e('Run Security Scan', 'cadssl'); ?>
                        </a>
                        <a href="<?php echo admin_url('admin.php?page=cadssl-malware-scanner'); ?>" class="button">
                            <?php _e('Run Malware Scan', 'cadssl'); ?>
                        </a>
                    </p>
                </div>
                <?php endif; ?>
                
                <?php if (!$displayed_cards['quick_actions']): $displayed_cards['quick_actions'] = true; ?>
                <!-- Quick Actions Card -->
                <div class="cadssl-dashboard-card">
                    <h2><?php _e('Quick Actions', 'cadssl'); ?></h2>
                    <ul class="cadssl-dashboard-actions">
                        <li>
                            <a href="<?php echo admin_url('admin.php?page=cadssl-settings'); ?>">
                                <span class="dashicons dashicons-admin-generic"></span>
                                <?php _e('SSL Settings', 'cadssl'); ?>
                            </a>
                        </li>
                        <li>
                            <a href="<?php echo admin_url('admin.php?page=cadssl-advanced-headers'); ?>">
                                <span class="dashicons dashicons-shield"></span>
                                <?php _e('Security Headers', 'cadssl'); ?>
                            </a>
                        </li>
                        <li>
                            <a href="<?php echo admin_url('admin.php?page=cadssl-malware-scanner'); ?>">
                                <span class="dashicons dashicons-code-standards"></span>
                                <?php _e('Malware Scanner', 'cadssl'); ?>
                            </a>
                        </li>
                        <li>
                            <a href="<?php echo admin_url('admin.php?page=cadssl-file-permissions'); ?>">
                                <span class="dashicons dashicons-admin-users"></span>
                                <?php _e('File Permissions', 'cadssl'); ?>
                            </a>
                        </li>
                    </ul>
                </div>
                <?php endif; ?>
            </div>
            
            <?php if (count($issues) > 0): ?>
            <div class="cadssl-dashboard-issues">
                <h2><?php _e('Security Issues', 'cadssl'); ?></h2>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th><?php _e('Issue', 'cadssl'); ?></th>
                            <th><?php _e('Severity', 'cadssl'); ?></th>
                            <th><?php _e('Description', 'cadssl'); ?></th>
                            <th><?php _e('Actions', 'cadssl'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($issues as $issue): ?>
                            <tr>
                                <td><?php echo esc_html($issue['title']); ?></td>
                                <td>
                                    <?php if ($issue['status'] === 'critical'): ?>
                                        <span class="cadssl-status-critical">
                                            <?php _e('Critical', 'cadssl'); ?>
                                        </span>
                                    <?php elseif ($issue['status'] === 'warning'): ?>
                                        <span class="cadssl-status-warning">
                                            <?php _e('Warning', 'cadssl'); ?>
                                        </span>
                                    <?php else: ?>
                                        <span class="cadssl-status-info">
                                            <?php _e('Info', 'cadssl'); ?>
                                        </span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo esc_html($issue['description']); ?></td>
                                <td>
                                    <?php if (!empty($issue['action_url']) && !empty($issue['action_text'])): ?>
                                        <a href="<?php echo esc_url($issue['action_url']); ?>" class="button button-small">
                                            <?php echo esc_html($issue['action_text']); ?>
                                        </a>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php endif; ?>
            
            <style>
                .cadssl-dashboard-header {
                    display: flex;
                    margin-bottom: 20px;
                }
                .cadssl-dashboard-score-container {
                    text-align: center;
                    margin-right: 30px;
                }
                .cadssl-dashboard-score {
                    position: relative;
                    width: 150px;
                    height: 150px;
                    border-radius: 50%;
                    background: #f0f0f1;
                    margin-bottom: 10px;
                }
                .cadssl-dashboard-score-circle {
                    position: absolute;
                    top: 15px;
                    left: 15px;
                    width: 120px;
                    height: 120px;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: white;
                    font-size: 36px;
                    font-weight: bold;
                }
                .cadssl-dashboard-summary {
                    flex: 1;
                }
                .cadssl-dashboard-cards {
                    display: flex;
                    flex-wrap: wrap;
                    margin: 0 -10px;
                }
                .cadssl-dashboard-card {
                    width: calc(33.333% - 20px);
                    margin: 0 10px 20px;
                    padding: 20px;
                    background: white;
                    border: 1px solid #e5e5e5;
                    box-sizing: border-box;
                }
                .cadssl-dashboard-status-positive {
                    color: #46b450;
                    font-weight: bold;
                }
                .cadssl-dashboard-status-negative {
                    color: #dc3232;
                    font-weight: bold;
                }
                .cadssl-dashboard-card-actions {
                    margin-top: 15px;
                }
                .cadssl-dashboard-actions {
                    list-style: none;
                    margin: 0;
                    padding: 0;
                }
                .cadssl-dashboard-actions li {
                    margin-bottom: 10px;
                }
                .cadssl-dashboard-actions a {
                    display: flex;
                    align-items: center;
                    text-decoration: none;
                    color: #2271b1;
                }
                .cadssl-dashboard-actions .dashicons {
                    margin-right: 5px;
                }
                .cadssl-status-critical {
                    color: white;
                    background-color: #dc3232;
                    padding: 3px 8px;
                    border-radius: 3px;
                    font-size: 12px;
                    font-weight: bold;
                }
                .cadssl-status-warning {
                    color: white;
                    background-color: #ffb900;
                    padding: 3px 8px;
                    border-radius: 3px;
                    font-size: 12px;
                    font-weight: bold;
                }
                .cadssl-status-info {
                    color: white;
                    background-color: #72aee6;
                    padding: 3px 8px;
                    border-radius: 3px;
                    font-size: 12px;
                    font-weight: bold;
                }
                
                @media screen and (max-width: 782px) {
                    .cadssl-dashboard-header {
                        flex-direction: column;
                    }
                    .cadssl-dashboard-score-container {
                        margin-right: 0;
                        margin-bottom: 20px;
                    }
                    .cadssl-dashboard-card {
                        width: 100%;
                        margin-bottom: 20px;
                    }
                }
            </style>
        </div>
        <?php
    }
    
    /**
     * Add security status to admin bar
     * 
     * @param WP_Admin_Bar $admin_bar Admin bar object
     */
    public function add_admin_bar_security_status($admin_bar) {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        $security_status = $this->get_security_status();
        $score = $security_status['score'];
        $critical_issues = array_filter($security_status['issues'], function($issue) {
            return $issue['status'] === 'critical';
        });
        
        // Determine status color and icon
        if ($score < 60) {
            $status_class = 'cadssl-status-critical';
            $status_text = __('Critical', 'cadssl');
            $dashicon = 'dashicons-warning';
        } elseif ($score < 80) {
            $status_class = 'cadssl-status-warning';
            $status_text = __('Warning', 'cadssl');
            $dashicon = 'dashicons-flag';
        } else {
            $status_class = 'cadssl-status-good';
            $status_text = __('Good', 'cadssl');
            $dashicon = 'dashicons-shield';
        }
        
        // Add main item
        $admin_bar->add_node(array(
            'id'    => 'cadssl-security',
            'title' => sprintf(
                '<span class="ab-icon dashicons %s"></span><span class="ab-label">%s: %s</span>',
                esc_attr($dashicon),
                __('Security', 'cadssl'),
                esc_html($status_text)
            ),
            'href'  => admin_url('admin.php?page=cadssl-dashboard'),
            'meta'  => array(
                'class' => $status_class
            )
        ));
        
        // Add submenu items
        if (!empty($critical_issues)) {
            $admin_bar->add_node(array(
                'id'     => 'cadssl-critical-issues',
                'parent' => 'cadssl-security',
                'title'  => sprintf(
                    __('%d Critical Issues', 'cadssl'),
                    count($critical_issues)
                ),
                'href'   => admin_url('admin.php?page=cadssl-dashboard'),
                'meta'   => array(
                    'class' => 'cadssl-admin-bar-warning'
                )
            ));
        }
        
        $admin_bar->add_node(array(
            'id'     => 'cadssl-dashboard',
            'parent' => 'cadssl-security',
            'title'  => __('Security Dashboard', 'cadssl'),
            'href'   => admin_url('admin.php?page=cadssl-dashboard')
        ));
        
        $admin_bar->add_node(array(
            'id'     => 'cadssl-malware-scanner',
            'parent' => 'cadssl-security',
            'title'  => __('Malware Scanner', 'cadssl'),
            'href'   => admin_url('admin.php?page=cadssl-malware-scanner')
        ));
        
        $admin_bar->add_node(array(
            'id'     => 'cadssl-settings',
            'parent' => 'cadssl-security',
            'title'  => __('Security Settings', 'cadssl'),
            'href'   => admin_url('admin.php?page=cadssl-settings')
        ));
        
        // Add inline styles
        ?>
        <style>
            .cadssl-status-critical .ab-icon {
                color: #dc3232 !important;
            }
            .cadssl-status-warning .ab-icon {
                color: #ffb900 !important;
            }
            .cadssl-status-good .ab-icon {
                color: #46b450 !important;
            }
            .cadssl-admin-bar-warning {
                color: #dc3232 !important;
            }
        </style>
        <?php
    }
    
    /**
     * Get security status and score
     * 
     * @return array Security status data
     */
    public function get_security_status() {
        // Initialize scanner if needed
        if (!class_exists('CADSSL_Security_Scanner')) {
            require_once CADSSL_PATH . 'includes/class-cadssl-security-scanner.php';
        }
        
        // Get security scan results or run new scan if needed
        $results = get_option('cadssl_last_scan_results');
        if (!$results) {
            $scanner = new CADSSL_Security_Scanner();
            $results = $scanner->run_security_scan();
            update_option('cadssl_last_scan_results', $results);
            update_option('cadssl_last_scan_time', date('Y-m-d H:i:s'));
        }
        
        // Collect all check results into a flat array
        $all_checks = array();
        $issues = array();
        $passed = array();
        
        foreach ($results as $category => $checks) {
            foreach ($checks as $check) {
                $all_checks[] = $check;
                
                if ($check['status'] === 'warning' || $check['status'] === 'critical') {
                    $issues[] = $check;
                } else {
                    $passed[] = $check;
                }
            }
        }
        
        // Calculate security score (percentage of passed checks)
        $total_checks = count($all_checks);
        $score = $total_checks > 0 ? (count($passed) / $total_checks) * 100 : 100;
        
        // Apply penalty for critical issues
        $critical_count = 0;
        foreach ($issues as $issue) {
            if ($issue['status'] === 'critical') {
                $critical_count++;
            }
        }
        
        // Each critical issue reduces score by 10%
        $score = max(0, $score - ($critical_count * 10));
        
        return array(
            'score' => round($score),
            'issues' => $issues,
            'passed' => $passed,
            'total' => $total_checks
        );
    }
}