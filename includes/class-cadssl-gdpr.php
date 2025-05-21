<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * GDPR Compliance Module
 */
class CADSSL_GDPR {
    /**
     * Initialize GDPR module
     */
    public function init() {
        // Add admin menu
        add_action('admin_menu', array($this, 'add_gdpr_menu'), 22);
        
        // Register settings
        add_action('admin_init', array($this, 'register_settings'));
        
        // Apply GDPR features if enabled
        $options = get_option('cadssl_gdpr_options', array());
        
        if (isset($options['enable_gdpr_features']) && $options['enable_gdpr_features']) {
            // Add cookie notice if enabled
            if (isset($options['enable_cookie_notice']) && $options['enable_cookie_notice']) {
                add_action('wp_footer', array($this, 'display_cookie_notice'));
            }
            
            // Add privacy policy page link to footer
            if (isset($options['enable_privacy_policy_link']) && $options['enable_privacy_policy_link']) {
                add_action('wp_footer', array($this, 'add_privacy_policy_link'));
            }
            
            // Add data export and erasure functionality
            add_filter('wp_privacy_personal_data_exporters', array($this, 'register_data_exporter'));
            add_filter('wp_privacy_personal_data_erasers', array($this, 'register_data_eraser'));
            
            // Add cookie expiration controls
            add_filter('auth_cookie_expiration', array($this, 'modify_cookie_expiration'), 10, 3);
        }
        
        // Add GDPR compliance check to security scanner
        add_filter('cadssl_security_scan_results', array($this, 'add_gdpr_compliance_checks'));

        // Schedule data retention cleanup
        $this->schedule_data_retention();
    }
    
    /**
     * Add GDPR submenu
     */
    public function add_gdpr_menu() {
        // Make sure the parent menu exists
        global $submenu;
        if (!isset($submenu['cadssl-settings'])) {
            return;
        }
        
        add_submenu_page(
            'cadssl-settings',
            __('GDPR Compliance', 'cadssl'),
            __('GDPR Compliance', 'cadssl'),
            'manage_options',
            'cadssl-gdpr',
            array($this, 'display_gdpr_page')
        );
    }
    
    /**
     * Register GDPR settings
     */
    public function register_settings() {
        register_setting('cadssl_gdpr_options', 'cadssl_gdpr_options');
        
        // General GDPR section
        add_settings_section(
            'cadssl_gdpr_general',
            __('GDPR Compliance Settings', 'cadssl'),
            array($this, 'gdpr_section_callback'),
            'cadssl-gdpr'
        );
        
        // Enable GDPR Features
        add_settings_field(
            'enable_gdpr_features',
            __('Enable GDPR Features', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-gdpr',
            'cadssl_gdpr_general',
            array(
                'id' => 'enable_gdpr_features',
                'description' => __('Enable GDPR compliance features', 'cadssl')
            )
        );
        
        // Enable Cookie Notice
        add_settings_field(
            'enable_cookie_notice',
            __('Cookie Notice', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-gdpr',
            'cadssl_gdpr_general',
            array(
                'id' => 'enable_cookie_notice',
                'description' => __('Display cookie consent notice to visitors', 'cadssl')
            )
        );
        
        // Cookie Notice Text
        add_settings_field(
            'cookie_notice_text',
            __('Cookie Notice Text', 'cadssl'),
            array($this, 'textarea_callback'),
            'cadssl-gdpr',
            'cadssl_gdpr_general',
            array(
                'id' => 'cookie_notice_text',
                'description' => __('Text to display in the cookie notice', 'cadssl'),
                'default' => __('This website uses cookies to ensure you get the best experience on our website.', 'cadssl')
            )
        );
        
        // Enable Privacy Policy Link
        add_settings_field(
            'enable_privacy_policy_link',
            __('Privacy Policy Link', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-gdpr',
            'cadssl_gdpr_general',
            array(
                'id' => 'enable_privacy_policy_link',
                'description' => __('Add privacy policy link to footer', 'cadssl')
            )
        );
        
        // Privacy Policy Page
        $pages = get_pages();
        $page_options = array();
        foreach ($pages as $page) {
            $page_options[$page->ID] = $page->post_title;
        }
        
        add_settings_field(
            'privacy_policy_page',
            __('Privacy Policy Page', 'cadssl'),
            array($this, 'select_callback'),
            'cadssl-gdpr',
            'cadssl_gdpr_general',
            array(
                'id' => 'privacy_policy_page',
                'description' => __('Select your privacy policy page', 'cadssl'),
                'options' => $page_options
            )
        );
        
        // Cookie Expiration section
        add_settings_section(
            'cadssl_cookie_expiration',
            __('Cookie Expiration Settings', 'cadssl'),
            array($this, 'cookie_expiration_section_callback'),
            'cadssl-gdpr'
        );
        
        // Cookie Expiration Time
        add_settings_field(
            'cookie_expiration_days',
            __('Cookie Expiration', 'cadssl'),
            array($this, 'number_callback'),
            'cadssl-gdpr',
            'cadssl_cookie_expiration',
            array(
                'id' => 'cookie_expiration_days',
                'description' => __('Number of days until authentication cookies expire', 'cadssl'),
                'default' => 14,
                'min' => 1,
                'max' => 365
            )
        );
        
        // Data Protection section
        add_settings_section(
            'cadssl_data_protection',
            __('Data Protection Settings', 'cadssl'),
            array($this, 'data_protection_section_callback'),
            'cadssl-gdpr'
        );
        
        // Data Retention Period
        add_settings_field(
            'data_retention_period',
            __('Data Retention Period', 'cadssl'),
            array($this, 'number_callback'),
            'cadssl-gdpr',
            'cadssl_data_protection',
            array(
                'id' => 'data_retention_period',
                'description' => __('Number of days to retain user data (0 = indefinite)', 'cadssl'),
                'default' => 0,
                'min' => 0,
                'max' => 3650
            )
        );
        
        // Enable Data Access
        add_settings_field(
            'enable_data_access',
            __('Data Access', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-gdpr',
            'cadssl_data_protection',
            array(
                'id' => 'enable_data_access',
                'description' => __('Allow users to request their data', 'cadssl')
            )
        );
        
        // Enable Data Deletion
        add_settings_field(
            'enable_data_deletion',
            __('Data Deletion', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-gdpr',
            'cadssl_data_protection',
            array(
                'id' => 'enable_data_deletion',
                'description' => __('Allow users to request data deletion', 'cadssl')
            )
        );
    }
    
    /**
     * GDPR section callback
     */
    public function gdpr_section_callback() {
        echo '<p>' . __('Configure GDPR compliance settings for your website.', 'cadssl') . '</p>';
    }
    
    /**
     * Cookie expiration section callback
     */
    public function cookie_expiration_section_callback() {
        echo '<p>' . __('Control how long authentication cookies are stored on user devices.', 'cadssl') . '</p>';
    }
    
    /**
     * Data protection section callback
     */
    public function data_protection_section_callback() {
        echo '<p>' . __('Configure how user data is handled and retained on your site.', 'cadssl') . '</p>';
    }
    
    /**
     * Checkbox field callback
     */
    public function checkbox_callback($args) {
        $options = get_option('cadssl_gdpr_options', array());
        $id = $args['id'];
        $checked = isset($options[$id]) ? $options[$id] : false;
        
        echo '<input type="checkbox" id="cadssl_gdpr_options_' . esc_attr($id) . '" name="cadssl_gdpr_options[' . esc_attr($id) . ']" value="1" ' . checked(1, $checked, false) . '/>';
        echo '<label for="cadssl_gdpr_options_' . esc_attr($id) . '">' . esc_html($args['description']) . '</label>';
    }
    
    /**
     * Select field callback
     */
    public function select_callback($args) {
        $options = get_option('cadssl_gdpr_options', array());
        $id = $args['id'];
        $selected = isset($options[$id]) ? $options[$id] : '';
        
        echo '<select id="cadssl_gdpr_options_' . esc_attr($id) . '" name="cadssl_gdpr_options[' . esc_attr($id) . ']">';
        foreach ($args['options'] as $value => $label) {
            echo '<option value="' . esc_attr($value) . '" ' . selected($value, $selected, false) . '>' . esc_html($label) . '</option>';
        }
        echo '</select>';
        echo '<p class="description">' . esc_html($args['description']) . '</p>';
    }
    
    /**
     * Textarea field callback
     */
    public function textarea_callback($args) {
        $options = get_option('cadssl_gdpr_options', array());
        $id = $args['id'];
        $value = isset($options[$id]) ? $options[$id] : (isset($args['default']) ? $args['default'] : '');
        
        echo '<textarea id="cadssl_gdpr_options_' . esc_attr($id) . '" name="cadssl_gdpr_options[' . esc_attr($id) . ']" rows="4" style="width:100%;">' . esc_textarea($value) . '</textarea>';
        echo '<p class="description">' . esc_html($args['description']) . '</p>';
    }
    
    /**
     * Number field callback
     */
    public function number_callback($args) {
        $options = get_option('cadssl_gdpr_options', array());
        $id = $args['id'];
        $value = isset($options[$id]) ? $options[$id] : (isset($args['default']) ? $args['default'] : '');
        $min = isset($args['min']) ? 'min="' . intval($args['min']) . '"' : '';
        $max = isset($args['max']) ? 'max="' . intval($args['max']) . '"' : '';
        
        echo '<input type="number" id="cadssl_gdpr_options_' . esc_attr($id) . '" name="cadssl_gdpr_options[' . esc_attr($id) . ']" value="' . esc_attr($value) . '" ' . $min . ' ' . $max . '/>';
        echo '<p class="description">' . esc_html($args['description']) . '</p>';
    }
    
    /**
     * Display GDPR settings page
     */
    public function display_gdpr_page() {
        ?>
        <div class="wrap">
            <h1><?php _e('GDPR Compliance', 'cadssl'); ?></h1>
            
            <div class="notice notice-info">
                <p>
                    <?php _e('The General Data Protection Regulation (GDPR) is a regulation in EU law on data protection and privacy. This module helps your site comply with GDPR requirements.', 'cadssl'); ?>
                </p>
                <p>
                    <strong><?php _e('Note:', 'cadssl'); ?></strong>
                    <?php _e('This module provides tools to help with GDPR compliance, but full compliance depends on your specific data handling practices.', 'cadssl'); ?>
                </p>
            </div>
            
            <form method="post" action="options.php">
                <?php
                settings_fields('cadssl_gdpr_options');
                do_settings_sections('cadssl-gdpr');
                submit_button();
                ?>
            </form>
            
            <?php $this->display_gdpr_compliance_checker(); ?>
            
            <div class="card">
                <h2><?php _e('GDPR Resources', 'cadssl'); ?></h2>
                <ul>
                    <li><a href="https://gdpr.eu/" target="_blank"><?php _e('Official GDPR Portal', 'cadssl'); ?></a></li>
                    <li><a href="https://wordpress.org/support/article/wordpress-privacy/" target="_blank"><?php _e('WordPress Privacy Documentation', 'cadssl'); ?></a></li>
                    <li><a href="https://wordpress.org/plugins/wp-gdpr-compliance/" target="_blank"><?php _e('Additional WordPress GDPR Plugins', 'cadssl'); ?></a></li>
                </ul>
            </div>
        </div>
        <?php
    }
    
    /**
     * Display GDPR compliance checker
     */
    private function display_gdpr_compliance_checker() {
        $compliance_checks = $this->check_gdpr_compliance();
        $total_checks = count($compliance_checks);
        $passed_checks = 0;
        
        foreach ($compliance_checks as $check) {
            if ($check['status'] === 'passed') {
                $passed_checks++;
            }
        }
        
        $compliance_percentage = $total_checks > 0 ? round(($passed_checks / $total_checks) * 100) : 0;
        ?>
        <div class="card">
            <h2><?php _e('GDPR Compliance Check', 'cadssl'); ?></h2>
            
            <div class="cadssl-progress-bar">
                <div class="cadssl-progress" style="width: <?php echo esc_attr($compliance_percentage); ?>%;">
                    <?php echo esc_html($compliance_percentage); ?>%
                </div>
            </div>
            
            <style>
                .cadssl-progress-bar {
                    height: 25px;
                    background-color: #f1f1f1;
                    border-radius: 4px;
                    margin-bottom: 20px;
                }
                .cadssl-progress {
                    height: 100%;
                    background-color: #46b450;
                    border-radius: 4px;
                    text-align: center;
                    line-height: 25px;
                    color: white;
                    font-weight: bold;
                }
            </style>
            
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php _e('Check', 'cadssl'); ?></th>
                        <th><?php _e('Status', 'cadssl'); ?></th>
                        <th><?php _e('Recommendation', 'cadssl'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($compliance_checks as $check): ?>
                        <tr>
                            <td><?php echo esc_html($check['title']); ?></td>
                            <td>
                                <?php if ($check['status'] === 'passed'): ?>
                                    <span style="color:green;">✓ <?php _e('Passed', 'cadssl'); ?></span>
                                <?php else: ?>
                                    <span style="color:red;">✗ <?php _e('Failed', 'cadssl'); ?></span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo esc_html($check['recommendation']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php
    }
    
    /**
     * Check GDPR compliance
     * 
     * @return array Compliance check results
     */
    public function check_gdpr_compliance() {
        $options = get_option('cadssl_gdpr_options', array());
        $compliance_checks = array();
        
        // Check if privacy policy page exists
        $privacy_policy_id = isset($options['privacy_policy_page']) ? $options['privacy_policy_page'] : get_option('wp_page_for_privacy_policy');
        $has_privacy_policy = ($privacy_policy_id && get_post_status($privacy_policy_id) === 'publish');
        
        $compliance_checks[] = array(
            'title' => __('Privacy Policy', 'cadssl'),
            'status' => $has_privacy_policy ? 'passed' : 'failed',
            'recommendation' => $has_privacy_policy ? 
                __('You have a privacy policy page.', 'cadssl') : 
                __('Create a privacy policy page and set it in Settings > Privacy or in GDPR settings.', 'cadssl')
        );
        
        // Check if cookie notice is enabled
        $has_cookie_notice = isset($options['enable_cookie_notice']) && $options['enable_cookie_notice'];
        
        $compliance_checks[] = array(
            'title' => __('Cookie Consent', 'cadssl'),
            'status' => $has_cookie_notice ? 'passed' : 'failed',
            'recommendation' => $has_cookie_notice ? 
                __('Cookie notice is enabled.', 'cadssl') : 
                __('Enable the cookie notice in GDPR settings.', 'cadssl')
        );
        
        // Check if SSL is enabled
        $is_ssl = is_ssl();
        
        $compliance_checks[] = array(
            'title' => __('Secure Data Transfer', 'cadssl'),
            'status' => $is_ssl ? 'passed' : 'failed',
            'recommendation' => $is_ssl ? 
                __('Your site uses SSL for secure data transfer.', 'cadssl') : 
                __('Enable SSL to ensure secure data transfer.', 'cadssl')
        );
        
        // Check if data access is enabled
        $has_data_access = isset($options['enable_data_access']) && $options['enable_data_access'];
        
        $compliance_checks[] = array(
            'title' => __('Data Access Rights', 'cadssl'),
            'status' => $has_data_access ? 'passed' : 'failed',
            'recommendation' => $has_data_access ? 
                __('Users can request access to their data.', 'cadssl') : 
                __('Enable data access in GDPR settings.', 'cadssl')
        );
        
        // Check if data deletion is enabled
        $has_data_deletion = isset($options['enable_data_deletion']) && $options['enable_data_deletion'];
        
        $compliance_checks[] = array(
            'title' => __('Right to be Forgotten', 'cadssl'),
            'status' => $has_data_deletion ? 'passed' : 'failed',
            'recommendation' => $has_data_deletion ? 
                __('Users can request deletion of their data.', 'cadssl') : 
                __('Enable data deletion in GDPR settings.', 'cadssl')
        );
        
        // Check for contact form plugins
        $contact_form_7_active = is_plugin_active('contact-form-7/wp-contact-form-7.php');
        $wpforms_active = is_plugin_active('wpforms-lite/wpforms.php') || is_plugin_active('wpforms/wpforms.php');
        $has_contact_forms = $contact_form_7_active || $wpforms_active;
        
        $compliance_checks[] = array(
            'title' => __('Contact Form Compliance', 'cadssl'),
            'status' => $has_contact_forms ? 'passed' : 'passed', // Default to passed if no forms
            'recommendation' => $has_contact_forms ? 
                __('Make sure your contact forms include privacy policy checkbox and clear consent language.', 'cadssl') : 
                __('If you add contact forms, ensure they include privacy notices and consent checkboxes.', 'cadssl')
        );
        
        return $compliance_checks;
    }
    
    /**
     * Add GDPR compliance checks to security scanner
     * 
     * @param array $results Security scan results
     * @return array Updated scan results
     */
    public function add_gdpr_compliance_checks($results) {
        $compliance_checks = $this->check_gdpr_compliance();
        $gdpr_results = array();
        
        foreach ($compliance_checks as $check) {
            $gdpr_results[] = array(
                'title' => $check['title'],
                'description' => $check['recommendation'],
                'status' => $check['status'] === 'passed' ? 'success' : 'warning',
                'action_url' => admin_url('admin.php?page=cadssl-gdpr'),
                'action_text' => __('GDPR Settings', 'cadssl')
            );
        }
        
        $results['gdpr'] = $gdpr_results;
        return $results;
    }
    
    /**
     * Display cookie notice
     */
    public function display_cookie_notice() {
        // Don't show notice if user has already accepted
        if (isset($_COOKIE['cadssl_cookie_notice_accepted'])) {
            return;
        }
        
        $options = get_option('cadssl_gdpr_options', array());
        $notice_text = isset($options['cookie_notice_text']) ? $options['cookie_notice_text'] : __('This website uses cookies to ensure you get the best experience on our website.', 'cadssl');
        
        // Get privacy policy URL
        $privacy_policy_id = isset($options['privacy_policy_page']) ? $options['privacy_policy_page'] : get_option('wp_page_for_privacy_policy');
        $privacy_policy_url = $privacy_policy_id ? get_permalink($privacy_policy_id) : '';
        
        ?>
        <div id="cadssl-cookie-notice">
            <div class="cadssl-cookie-notice-container">
                <div class="cadssl-cookie-notice-content">
                    <p><?php echo esc_html($notice_text); ?></p>
                    
                    <?php if ($privacy_policy_url): ?>
                        <p><a href="<?php echo esc_url($privacy_policy_url); ?>" target="_blank"><?php _e('Privacy Policy', 'cadssl'); ?></a></p>
                    <?php endif; ?>
                </div>
                
                <div class="cadssl-cookie-notice-actions">
                    <button id="cadssl-accept-cookies" class="button"><?php _e('Accept', 'cadssl'); ?></button>
                </div>
            </div>
        </div>
        
        <style>
            #cadssl-cookie-notice {
                position: fixed;
                bottom: 0;
                left: 0;
                width: 100%;
                background-color: rgba(0, 0, 0, 0.8);
                color: #fff;
                z-index: 999999;
                padding: 15px;
            }
            .cadssl-cookie-notice-container {
                max-width: 1200px;
                margin: 0 auto;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
            }
            .cadssl-cookie-notice-content {
                flex: 1;
                padding-right: 20px;
            }
            .cadssl-cookie-notice-content p {
                margin: 0 0 5px;
                font-size: 14px;
            }
            .cadssl-cookie-notice-content a {
                color: #fff;
                text-decoration: underline;
            }
            .cadssl-cookie-notice-actions {
                padding: 10px 0;
            }
            @media (max-width: 768px) {
                .cadssl-cookie-notice-container {
                    flex-direction: column;
                }
                .cadssl-cookie-notice-content {
                    padding-right: 0;
                    padding-bottom: 10px;
                }
            }
        </style>
        
        <script>
            document.getElementById('cadssl-accept-cookies').addEventListener('click', function() {
                // Set cookie for 30 days
                var date = new Date();
                date.setTime(date.getTime() + (30 * 24 * 60 * 60 * 1000));
                document.cookie = "cadssl_cookie_notice_accepted=1; expires=" + date.toUTCString() + "; path=/; SameSite=Lax";
                
                // Hide notice
                document.getElementById('cadssl-cookie-notice').style.display = 'none';
            });
        </script>
        <?php
    }
    
    /**
     * Add privacy policy link to footer
     */
    public function add_privacy_policy_link() {
        $options = get_option('cadssl_gdpr_options', array());
        $privacy_policy_id = isset($options['privacy_policy_page']) ? $options['privacy_policy_page'] : get_option('wp_page_for_privacy_policy');
        
        if ($privacy_policy_id) {
            $privacy_policy_url = get_permalink($privacy_policy_id);
            
            if ($privacy_policy_url) {
                echo '<div class="cadssl-privacy-policy-link">';
                echo '<a href="' . esc_url($privacy_policy_url) . '">' . __('Privacy Policy', 'cadssl') . '</a>';
                echo '</div>';
                
                echo '<style>';
                echo '.cadssl-privacy-policy-link { text-align: center; padding: 10px 0; }';
                echo '</style>';
            }
        }
    }
    
    /**
     * Register personal data exporter
     * 
     * @param array $exporters Current exporters
     * @return array Updated exporters
     */
    public function register_data_exporter($exporters) {
        $options = get_option('cadssl_gdpr_options', array());
        
        if (isset($options['enable_data_access']) && $options['enable_data_access']) {
            $exporters['cadssl'] = array(
                'exporter_friendly_name' => __('CADSSL Security Data', 'cadssl'),
                'callback' => array($this, 'export_personal_data'),
            );
        }
        
        return $exporters;
    }
    
    /**
     * Export personal data
     * 
     * @param string $email_address User's email address
     * @param int $page Page number
     * @return array Data export
     */
    public function export_personal_data($email_address, $page = 1) {
        $user = get_user_by('email', $email_address);
        $export_items = array();
        
        if ($user) {
            // Get user security log data (example)
            $security_data = array(
                array(
                    'name' => __('Last Login', 'cadssl'),
                    'value' => get_user_meta($user->ID, 'cadssl_last_login', true)
                ),
                array(
                    'name' => __('Login IP', 'cadssl'),
                    'value' => get_user_meta($user->ID, 'cadssl_last_ip', true)
                ),
            );
            
            $export_items[] = array(
                'group_id' => 'cadssl-security-data',
                'group_label' => __('Security Data', 'cadssl'),
                'item_id' => "cadssl-{$user->ID}",
                'data' => $security_data,
            );
        }
        
        return array(
            'data' => $export_items,
            'done' => true,
        );
    }
    
    /**
     * Register personal data eraser
     * 
     * @param array $erasers Current erasers
     * @return array Updated erasers
     */
    public function register_data_eraser($erasers) {
        $options = get_option('cadssl_gdpr_options', array());
        
        if (isset($options['enable_data_deletion']) && $options['enable_data_deletion']) {
            $erasers['cadssl'] = array(
                'eraser_friendly_name' => __('CADSSL Security Data', 'cadssl'),
                'callback' => array($this, 'erase_personal_data'),
            );
        }
        
        return $erasers;
    }
    
    /**
     * Erase personal data
     * 
     * @param string $email_address User's email address
     * @param int $page Page number
     * @return array Erasure results
     */
    public function erase_personal_data($email_address, $page = 1) {
        $user = get_user_by('email', $email_address);
        $items_removed = false;
        $items_retained = false;
        $messages = array();
        
        if ($user) {
            // Remove user security log data (example)
            delete_user_meta($user->ID, 'cadssl_last_login');
            delete_user_meta($user->ID, 'cadssl_last_ip');
            
            $items_removed = true;
            $messages[] = __('CADSSL security data removed.', 'cadssl');
        }
        
        return array(
            'items_removed' => $items_removed,
            'items_retained' => $items_retained,
            'messages' => $messages,
            'done' => true,
        );
    }
    
    /**
     * Modify cookie expiration time
     * 
     * @param int $expiration Default expiration time in seconds
     * @param int $user_id User ID
     * @param bool $remember Whether to remember the user
     * @return int Modified expiration time
     */
    public function modify_cookie_expiration($expiration, $user_id, $remember) {
        $options = get_option('cadssl_gdpr_options', array());
        
        if (isset($options['cookie_expiration_days']) && intval($options['cookie_expiration_days']) > 0) {
            // Override the cookie expiration with our custom setting
            // Convert days to seconds
            $expiration = intval($options['cookie_expiration_days']) * DAY_IN_SECONDS;
        }
        
        return $expiration;
    }
    
    /**
     * Implement data retention cleanup
     * This can be scheduled to run periodically
     */
    public function handle_data_retention() {
        $options = get_option('cadssl_gdpr_options', array());
        
        if (isset($options['data_retention_period']) && intval($options['data_retention_period']) > 0) {
            $retention_days = intval($options['data_retention_period']);
            $cutoff_date = date('Y-m-d H:i:s', strtotime("-$retention_days days"));
            
            // Example: Clean up old user activity logs
            global $wpdb;
            $table_name = $wpdb->prefix . 'cadssl_user_logs';
            
            if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") == $table_name) {
                $wpdb->query(
                    $wpdb->prepare(
                        "DELETE FROM $table_name WHERE log_time < %s",
                        $cutoff_date
                    )
                );
            }
            
            // You might want to add more cleanup actions here
            do_action('cadssl_data_retention_cleanup', $cutoff_date);
        }
    }
    
    /**
     * Schedule data retention cleanup
     */
    public function schedule_data_retention() {
        // Set up schedule if not already scheduled
        if (!wp_next_scheduled('cadssl_weekly_data_retention')) {
            wp_schedule_event(time(), 'weekly', 'cadssl_weekly_data_retention');
        }
        
        // Add action hook
        add_action('cadssl_weekly_data_retention', array($this, 'handle_data_retention'));
    }
}