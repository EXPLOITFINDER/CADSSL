<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class CADSSL_Admin {
    /**
     * Initialize admin functionality
     */
    public function init() {
        // Add settings page
        add_action('admin_menu', array($this, 'add_settings_page'), 10);
        
        // Register settings
        add_action('admin_init', array($this, 'register_settings'));
        
        // Add setting link on plugin page - with safety check for constant
        if (defined('CADSSL_BASENAME')) {
            add_filter('plugin_action_links_' . CADSSL_BASENAME, array($this, 'add_plugin_action_links'));
        } else {
            // Fallback if constant isn't defined
            $basename = plugin_basename(dirname(dirname(__FILE__)) . '/ssl.php');
            add_filter('plugin_action_links_' . $basename, array($this, 'add_plugin_action_links'));
        }
        
        // Load admin assets
        add_action('admin_enqueue_scripts', array($this, 'admin_assets'));
        
        // Add an admin notice tracker to prevent duplicate registrations
        if (!defined('CADSSL_ADMIN_MENUS')) {
            define('CADSSL_ADMIN_MENUS', array());
        }
    }
    
    /**
     * Add settings page
     */
    public function add_settings_page() {
        // Add main menu page if not already added
        $main_menu_slug = 'cadssl-settings';
        
        // Use a static property to track menu registration across instances
        static $registered_menus = array();
        
        // Only register the menu if it hasn't been registered yet
        if (!isset($registered_menus[$main_menu_slug])) {
            add_menu_page(
                __('CADSSL Security', 'cadssl'),
                __('CADSSL Security', 'cadssl'),
                'manage_options',
                $main_menu_slug,
                array($this, 'display_settings_page'),
                'dashicons-shield',
                80
            );
            
            $registered_menus[$main_menu_slug] = true;
        }
        
        // Add SSL settings as a submenu page
        add_submenu_page(
            $main_menu_slug,
            __('SSL Settings', 'cadssl'),
            __('SSL Settings', 'cadssl'),
            'manage_options',
            $main_menu_slug,
            array($this, 'display_settings_page')
        );
        
        // Only register other submenus if they haven't been registered yet
        if (!isset($registered_menus['cadssl-ssl-status'])) {
            add_submenu_page(
                $main_menu_slug,
                __('SSL Status', 'cadssl'),
                __('SSL Status', 'cadssl'),
                'manage_options',
                'cadssl-ssl-status',
                array($this, 'display_ssl_status_page')
            );
            
            $registered_menus['cadssl-ssl-status'] = true;
        }
        
        if (!isset($registered_menus['cadssl-security-scanner'])) {
            add_submenu_page(
                $main_menu_slug,
                __('Security Scanner', 'cadssl'),
                __('Security Scanner', 'cadssl'),
                'manage_options',
                'cadssl-security-scanner',
                array($this, 'display_security_scanner_page')
            );
            
            $registered_menus['cadssl-security-scanner'] = true;
        }
    }
    
    /**
     * Register plugin settings
     */
    public function register_settings() {
        register_setting('cadssl_options', 'cadssl_options');
        
        // General SSL section
        add_settings_section(
            'cadssl_general',
            __('General SSL Settings', 'cadssl'),
            array($this, 'general_section_callback'),
            'cadssl-settings'
        );
        
        add_settings_field(
            'force_ssl',
            __('Force SSL', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-settings',
            'cadssl_general',
            array(
                'id' => 'force_ssl',
                'description' => __('Automatically redirect HTTP to HTTPS', 'cadssl')
            )
        );
        
        add_settings_field(
            'secure_cookies',
            __('Secure Cookies', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-settings',
            'cadssl_general',
            array(
                'id' => 'secure_cookies',
                'description' => __('Set HttpOnly and Secure flags for cookies', 'cadssl')
            )
        );
        
        // HSTS section
        add_settings_section(
            'cadssl_hsts',
            __('HTTP Strict Transport Security (HSTS)', 'cadssl'),
            array($this, 'hsts_section_callback'),
            'cadssl-settings'
        );
        
        add_settings_field(
            'enable_hsts',
            __('Enable HSTS', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-settings',
            'cadssl_hsts',
            array(
                'id' => 'enable_hsts',
                'description' => __('Enable HTTP Strict Transport Security', 'cadssl')
            )
        );
        
        add_settings_field(
            'hsts_max_age',
            __('HSTS Max Age', 'cadssl'),
            array($this, 'number_callback'),
            'cadssl-settings',
            'cadssl_hsts',
            array(
                'id' => 'hsts_max_age',
                'description' => __('Max-Age in seconds (31536000 = 1 year)', 'cadssl'),
                'default' => 31536000
            )
        );
        
        add_settings_field(
            'hsts_subdomains',
            __('Include Subdomains', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-settings',
            'cadssl_hsts',
            array(
                'id' => 'hsts_subdomains',
                'description' => __('Apply HSTS to all subdomains', 'cadssl')
            )
        );
        
        add_settings_field(
            'hsts_preload',
            __('HSTS Preload', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-settings',
            'cadssl_hsts',
            array(
                'id' => 'hsts_preload',
                'description' => __('Add preload directive (required for HSTS preload list submission)', 'cadssl')
            )
        );
        
        // Security Headers section
        add_settings_section(
            'cadssl_security_headers',
            __('Security Headers', 'cadssl'),
            array($this, 'security_headers_section_callback'),
            'cadssl-settings'
        );
        
        add_settings_field(
            'security_headers',
            __('Enable Security Headers', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-settings',
            'cadssl_security_headers',
            array(
                'id' => 'security_headers',
                'description' => __('Add recommended security headers to your site', 'cadssl')
            )
        );
    }
    
    /**
     * General section callback
     */
    public function general_section_callback() {
        echo '<p>' . __('Configure basic SSL settings for your WordPress site.', 'cadssl') . '</p>';
    }
    
    /**
     * HSTS section callback
     */
    public function hsts_section_callback() {
        echo '<p>' . __('HTTP Strict Transport Security (HSTS) tells browsers to only use HTTPS for your domain. Use with caution as it can cause access issues if SSL is later disabled.', 'cadssl') . '</p>';
    }
    
    /**
     * Security Headers section callback
     */
    public function security_headers_section_callback() {
        echo '<p>' . __('Security headers help protect your site from common attacks.', 'cadssl') . '</p>';
    }
    
    /**
     * Checkbox field callback
     */
    public function checkbox_callback($args) {
        $options = get_option('cadssl_options');
        $id = $args['id'];
        $checked = isset($options[$id]) ? $options[$id] : false;
        
        echo '<input type="checkbox" id="cadssl_options_' . esc_attr($id) . '" name="cadssl_options[' . esc_attr($id) . ']" value="1" ' . checked(1, $checked, false) . '/>';
        echo '<label for="cadssl_options_' . esc_attr($id) . '">' . esc_html($args['description']) . '</label>';
    }
    
    /**
     * Number field callback
     */
    public function number_callback($args) {
        $options = get_option('cadssl_options');
        $id = $args['id'];
        $value = isset($options[$id]) ? $options[$id] : $args['default'];
        
        echo '<input type="number" id="cadssl_options_' . esc_attr($id) . '" name="cadssl_options[' . esc_attr($id) . ']" value="' . esc_attr($value) . '"/>';
        echo '<p class="description">' . esc_html($args['description']) . '</p>';
    }
    
    /**
     * Display the settings page
     */
    public function display_settings_page() {
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            <form action="options.php" method="post">
                <?php
                settings_fields('cadssl_options');
                do_settings_sections('cadssl-settings');
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }
    
    /**
     * Display the SSL status page
     */
    public function display_ssl_status_page() {
        $ssl_checker = new CADSSL_SSL_Checker();
        $ssl_status = $ssl_checker->check_ssl_status();
        ?>
        <div class="wrap">
            <h1><?php _e('SSL Status', 'cadssl'); ?></h1>
            <div class="notice <?php echo $ssl_status['is_ssl'] ? 'notice-success' : 'notice-error'; ?>">
                <p>
                    <?php 
                    if ($ssl_status['is_ssl']) {
                        _e('SSL is currently active on your site.', 'cadssl');
                    } else {
                        _e('SSL is NOT active on your site.', 'cadssl');
                    }
                    ?>
                </p>
            </div>
            
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php _e('Check', 'cadssl'); ?></th>
                        <th><?php _e('Status', 'cadssl'); ?></th>
                        <th><?php _e('Details', 'cadssl'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><?php _e('SSL Active', 'cadssl'); ?></td>
                        <td><?php echo $ssl_status['is_ssl'] ? '<span style="color:green">✓</span>' : '<span style="color:red">✗</span>'; ?></td>
                        <td><?php echo $ssl_status['is_ssl'] ? __('SSL is working properly', 'cadssl') : __('SSL is not active', 'cadssl'); ?></td>
                    </tr>
                    <tr>
                        <td><?php _e('Site URL', 'cadssl'); ?></td>
                        <td><?php echo $ssl_status['site_url_https'] ? '<span style="color:green">✓</span>' : '<span style="color:red">✗</span>'; ?></td>
                        <td><?php echo $ssl_status['site_url_https'] ? __('Site URL uses HTTPS', 'cadssl') : __('Site URL does not use HTTPS', 'cadssl'); ?></td>
                    </tr>
                    <tr>
                        <td><?php _e('Home URL', 'cadssl'); ?></td>
                        <td><?php echo $ssl_status['home_url_https'] ? '<span style="color:green">✓</span>' : '<span style="color:red">✗'; ?></td>
                        <td><?php echo $ssl_status['home_url_https'] ? __('Home URL uses HTTPS', 'cadssl') : __('Home URL does not use HTTPS', 'cadssl'); ?></td>
                    </tr>
                    <tr>
                        <td><?php _e('Mixed Content', 'cadssl'); ?></td>
                        <td><?php echo !$ssl_status['has_mixed_content'] ? '<span style="color:green">✓</span>' : '<span style="color:red">✗</span>'; ?></td>
                        <td><?php echo !$ssl_status['has_mixed_content'] ? __('No mixed content detected', 'cadssl') : __('Mixed content detected', 'cadssl'); ?></td>
                    </tr>
                </tbody>
            </table>
            
            <?php if ($ssl_status['certificate_info']): ?>
            <h2><?php _e('Certificate Information', 'cadssl'); ?></h2>
            <table class="wp-list-table widefat fixed striped">
                <tr>
                    <td><?php _e('Issuer', 'cadssl'); ?></td>
                    <td><?php echo esc_html($ssl_status['certificate_info']['issuer']); ?></td>
                </tr>
                <tr>
                    <td><?php _e('Subject', 'cadssl'); ?></td>
                    <td><?php echo esc_html($ssl_status['certificate_info']['subject']); ?></td>
                </tr>
                <tr>
                    <td><?php _e('Valid From', 'cadssl'); ?></td>
                    <td><?php echo esc_html($ssl_status['certificate_info']['valid_from']); ?></td>
                </tr>
                <tr>
                    <td><?php _e('Expires', 'cadssl'); ?></td>
                    <td><?php echo esc_html($ssl_status['certificate_info']['expires']); ?></td>
                </tr>
            </table>
            <?php endif; ?>
        </div>
        <?php
    }
    
    /**
     * Display security scanner page
     */
    public function display_security_scanner_page() {
        // ... existing code ...
    }
    
    /**
     * Display admin notices
     */
    public function display_admin_notices() {
        // Get SSL status
        $ssl_checker = new CADSSL_SSL_Checker();
        $ssl_status = $ssl_checker->check_ssl_status();
        
        // Show notice if SSL is not active
        if (!$ssl_status['is_ssl']) {
            ?>
            <div class="notice notice-error">
                <p>
                    <strong><?php _e('CADSSL Security:', 'cadssl'); ?></strong>
                    <?php _e('SSL is not active on your site. For maximum security, please install an SSL certificate.', 'cadssl'); ?>
                </p>
            </div>
            <?php
        }
        
        // Show notice if mixed content is detected
        if ($ssl_status['is_ssl'] && $ssl_status['has_mixed_content']) {
            ?>
            <div class="notice notice-warning">
                <p>
                    <strong><?php _e('CADSSL Security:', 'cadssl'); ?></strong>
                    <?php _e('Mixed content detected. Some resources are being loaded over insecure HTTP.', 'cadssl'); ?>
                </p>
            </div>
            <?php
        }
        
        // Show notice if site URL or home URL is not using HTTPS
        if ($ssl_status['is_ssl'] && (!$ssl_status['site_url_https'] || !$ssl_status['home_url_https'])) {
            ?>
            <div class="notice notice-warning">
                <p>
                    <strong><?php _e('CADSSL Security:', 'cadssl'); ?></strong>
                    <?php _e('Your site is using SSL but WordPress URLs are not set to HTTPS. Go to Settings > General to update them.', 'cadssl'); ?>
                </p>
            </div>
            <?php
        }
    }
    
    /**
     * Register admin assets (scripts and styles)
     */
    public function admin_assets($hook) {
        // ... existing code ...
    }

    /**
     * Add plugin action links
     *
     * @param array $links Default plugin action links
     * @return array Modified plugin action links
     */
    public function add_plugin_action_links($links) {
        $settings_link = '<a href="' . admin_url('admin.php?page=cadssl-settings') . '">' . __('Settings', 'cadssl') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }
}
