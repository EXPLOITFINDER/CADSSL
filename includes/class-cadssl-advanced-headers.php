<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Advanced Security Headers Implementation based on OWASP recommendations
 */
class CADSSL_Advanced_Headers {
    /**
     * Initialize advanced headers module
     */
    public function init() {
        // Add admin menu
        add_action('admin_menu', array($this, 'add_headers_menu'), 20);
        
        // Register settings
        add_action('admin_init', array($this, 'register_settings'));
        
        // Apply headers if enabled
        $options = get_option('cadssl_advanced_headers_options', array());
        if (isset($options['enable_advanced_headers']) && $options['enable_advanced_headers']) {
            add_action('send_headers', array($this, 'apply_advanced_headers'));
        }
    }
    
    /**
     * Add security headers submenu
     */
    public function add_headers_menu() {
        // Make sure the parent menu exists before adding submenu
        global $submenu;
        if (!isset($submenu['cadssl-settings'])) {
            return;
        }
        
        add_submenu_page(
            'cadssl-settings',
            __('Advanced Headers', 'cadssl'),
            __('Advanced Headers', 'cadssl'),
            'manage_options',
            'cadssl-advanced-headers',
            array($this, 'display_headers_page')
        );
    }
    
    /**
     * Register advanced headers settings
     */
    public function register_settings() {
        register_setting('cadssl_advanced_headers_options', 'cadssl_advanced_headers_options');
        
        // General Headers section
        add_settings_section(
            'cadssl_general_headers',
            __('Advanced Security Headers', 'cadssl'),
            array($this, 'headers_section_callback'),
            'cadssl-advanced-headers'
        );
        
        // Enable Advanced Headers
        add_settings_field(
            'enable_advanced_headers',
            __('Enable Advanced Headers', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-advanced-headers',
            'cadssl_general_headers',
            array(
                'id' => 'enable_advanced_headers',
                'description' => __('Apply advanced security headers to your site', 'cadssl')
            )
        );
        
        // Content-Security-Policy
        add_settings_field(
            'enable_csp',
            __('Content Security Policy (CSP)', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-advanced-headers',
            'cadssl_general_headers',
            array(
                'id' => 'enable_csp',
                'description' => __('Enable Content Security Policy header (recommended)', 'cadssl')
            )
        );
        
        add_settings_field(
            'csp_mode',
            __('CSP Mode', 'cadssl'),
            array($this, 'select_callback'),
            'cadssl-advanced-headers',
            'cadssl_general_headers',
            array(
                'id' => 'csp_mode',
                'description' => __('Choose between Enforcement mode or Report-Only mode to start', 'cadssl'),
                'options' => array(
                    'enforce' => __('Enforce Policy (blocks violations)', 'cadssl'),
                    'report-only' => __('Report-Only (monitors without blocking)', 'cadssl')
                )
            )
        );
        
        add_settings_field(
            'csp_policy',
            __('CSP Policy', 'cadssl'),
            array($this, 'textarea_callback'),
            'cadssl-advanced-headers',
            'cadssl_general_headers',
            array(
                'id' => 'csp_policy',
                'description' => __('Enter your Content Security Policy directives', 'cadssl'),
                'placeholder' => "default-src 'self'; script-src 'self' https://trusted-cdn.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
                'default' => "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
            )
        );
        
        // X-XSS-Protection
        add_settings_field(
            'enable_xss_protection',
            __('X-XSS-Protection', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-advanced-headers',
            'cadssl_general_headers',
            array(
                'id' => 'enable_xss_protection',
                'description' => __('Enable X-XSS-Protection header (legacy browsers)', 'cadssl')
            )
        );
        
        // X-Content-Type-Options
        add_settings_field(
            'enable_content_type_options',
            __('X-Content-Type-Options', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-advanced-headers',
            'cadssl_general_headers',
            array(
                'id' => 'enable_content_type_options',
                'description' => __('Enable X-Content-Type-Options header (prevents MIME-sniffing)', 'cadssl')
            )
        );
        
        // X-Frame-Options
        add_settings_field(
            'enable_frame_options',
            __('X-Frame-Options', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-advanced-headers',
            'cadssl_general_headers',
            array(
                'id' => 'enable_frame_options',
                'description' => __('Enable X-Frame-Options header (prevents clickjacking)', 'cadssl')
            )
        );
        
        add_settings_field(
            'frame_options_value',
            __('X-Frame-Options Value', 'cadssl'),
            array($this, 'select_callback'),
            'cadssl-advanced-headers',
            'cadssl_general_headers',
            array(
                'id' => 'frame_options_value',
                'description' => __('Select frame options policy', 'cadssl'),
                'options' => array(
                    'SAMEORIGIN' => __('SAMEORIGIN - Allow frames from same origin', 'cadssl'),
                    'DENY' => __('DENY - Deny all frames', 'cadssl')
                )
            )
        );
        
        // Referrer-Policy
        add_settings_field(
            'enable_referrer_policy',
            __('Referrer-Policy', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-advanced-headers',
            'cadssl_general_headers',
            array(
                'id' => 'enable_referrer_policy',
                'description' => __('Enable Referrer-Policy header (controls referrer information)', 'cadssl')
            )
        );
        
        add_settings_field(
            'referrer_policy_value',
            __('Referrer-Policy Value', 'cadssl'),
            array($this, 'select_callback'),
            'cadssl-advanced-headers',
            'cadssl_general_headers',
            array(
                'id' => 'referrer_policy_value',
                'description' => __('Select referrer policy', 'cadssl'),
                'options' => array(
                    'no-referrer' => __('no-referrer', 'cadssl'),
                    'no-referrer-when-downgrade' => __('no-referrer-when-downgrade', 'cadssl'),
                    'same-origin' => __('same-origin', 'cadssl'),
                    'origin' => __('origin', 'cadssl'),
                    'strict-origin' => __('strict-origin', 'cadssl'),
                    'origin-when-cross-origin' => __('origin-when-cross-origin', 'cadssl'),
                    'strict-origin-when-cross-origin' => __('strict-origin-when-cross-origin (recommended)', 'cadssl'),
                    'unsafe-url' => __('unsafe-url', 'cadssl')
                )
            )
        );
        
        // Permissions-Policy (formerly Feature-Policy)
        add_settings_field(
            'enable_permissions_policy',
            __('Permissions-Policy', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-advanced-headers',
            'cadssl_general_headers',
            array(
                'id' => 'enable_permissions_policy',
                'description' => __('Enable Permissions-Policy header (controls browser features)', 'cadssl')
            )
        );
        
        add_settings_field(
            'permissions_policy_value',
            __('Permissions-Policy Value', 'cadssl'),
            array($this, 'textarea_callback'),
            'cadssl-advanced-headers',
            'cadssl_general_headers',
            array(
                'id' => 'permissions_policy_value',
                'description' => __('Enter your Permissions-Policy directives', 'cadssl'),
                'placeholder' => "camera=(), microphone=(), geolocation=(self), accelerometer=()",
                'default' => "camera=(), microphone=(), geolocation=(), payment=()"
            )
        );
        
        // Clear-Site-Data
        add_settings_field(
            'enable_clear_site_data',
            __('Clear-Site-Data on Logout', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-advanced-headers',
            'cadssl_general_headers',
            array(
                'id' => 'enable_clear_site_data',
                'description' => __('Enable Clear-Site-Data header on logout (clears browser storage)', 'cadssl')
            )
        );
        
        // Cross-Origin policies section
        add_settings_section(
            'cadssl_cross_origin_headers',
            __('Cross-Origin Policies', 'cadssl'),
            array($this, 'cross_origin_section_callback'),
            'cadssl-advanced-headers'
        );
        
        // Cross-Origin-Embedder-Policy (COEP)
        add_settings_field(
            'enable_coep',
            __('Cross-Origin-Embedder-Policy', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-advanced-headers',
            'cadssl_cross_origin_headers',
            array(
                'id' => 'enable_coep',
                'description' => __('Enable Cross-Origin-Embedder-Policy (prevents loading cross-origin resources without explicit permission)', 'cadssl')
            )
        );
        
        add_settings_field(
            'coep_value',
            __('COEP Value', 'cadssl'),
            array($this, 'select_callback'),
            'cadssl-advanced-headers',
            'cadssl_cross_origin_headers',
            array(
                'id' => 'coep_value',
                'description' => __('Select COEP policy', 'cadssl'),
                'options' => array(
                    'require-corp' => __('require-corp - Requires CORP or CORS for cross-origin resources', 'cadssl'),
                    'credentialless' => __('credentialless - No credentials sent for cross-origin resources', 'cadssl')
                )
            )
        );
        
        // Cross-Origin-Opener-Policy (COOP)
        add_settings_field(
            'enable_coop',
            __('Cross-Origin-Opener-Policy', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-advanced-headers',
            'cadssl_cross_origin_headers',
            array(
                'id' => 'enable_coop',
                'description' => __('Enable Cross-Origin-Opener-Policy (controls window.opener relationship)', 'cadssl')
            )
        );
        
        add_settings_field(
            'coop_value',
            __('COOP Value', 'cadssl'),
            array($this, 'select_callback'),
            'cadssl-advanced-headers',
            'cadssl_cross_origin_headers',
            array(
                'id' => 'coop_value',
                'description' => __('Select COOP policy', 'cadssl'),
                'options' => array(
                    'same-origin' => __('same-origin - Isolates browsing context to same origin', 'cadssl'),
                    'same-origin-allow-popups' => __('same-origin-allow-popups - Allows popups', 'cadssl'),
                    'unsafe-none' => __('unsafe-none - Default behavior', 'cadssl')
                )
            )
        );
        
        // Cross-Origin-Resource-Policy (CORP)
        add_settings_field(
            'enable_corp',
            __('Cross-Origin-Resource-Policy', 'cadssl'),
            array($this, 'checkbox_callback'),
            'cadssl-advanced-headers',
            'cadssl_cross_origin_headers',
            array(
                'id' => 'enable_corp',
                'description' => __('Enable Cross-Origin-Resource-Policy (protects resources from being loaded by other origins)', 'cadssl')
            )
        );
        
        add_settings_field(
            'corp_value',
            __('CORP Value', 'cadssl'),
            array($this, 'select_callback'),
            'cadssl-advanced-headers',
            'cadssl_cross_origin_headers',
            array(
                'id' => 'corp_value',
                'description' => __('Select CORP policy', 'cadssl'),
                'options' => array(
                    'same-site' => __('same-site - Allow resources from same site', 'cadssl'),
                    'same-origin' => __('same-origin - Allow resources from same origin', 'cadssl'),
                    'cross-origin' => __('cross-origin - Allow resources from any origin', 'cadssl')
                )
            )
        );
    }
    
    /**
     * Headers section callback
     */
    public function headers_section_callback() {
        echo '<p>' . __('Configure advanced security headers based on OWASP recommendations. Advanced headers improve security beyond basic headers.', 'cadssl') . '</p>';
    }
    
    /**
     * Cross-Origin section callback
     */
    public function cross_origin_section_callback() {
        echo '<p>' . __('Cross-Origin policies help isolate your site from others and prevent various cross-origin attacks.', 'cadssl') . '</p>';
    }
    
    /**
     * Checkbox field callback
     */
    public function checkbox_callback($args) {
        $options = get_option('cadssl_advanced_headers_options', array());
        $id = $args['id'];
        $checked = isset($options[$id]) ? $options[$id] : false;
        
        echo '<input type="checkbox" id="cadssl_advanced_headers_options_' . esc_attr($id) . '" name="cadssl_advanced_headers_options[' . esc_attr($id) . ']" value="1" ' . checked(1, $checked, false) . '/>';
        echo '<label for="cadssl_advanced_headers_options_' . esc_attr($id) . '">' . esc_html($args['description']) . '</label>';
    }
    
    /**
     * Select field callback
     */
    public function select_callback($args) {
        $options = get_option('cadssl_advanced_headers_options', array());
        $id = $args['id'];
        $selected = isset($options[$id]) ? $options[$id] : '';
        
        echo '<select id="cadssl_advanced_headers_options_' . esc_attr($id) . '" name="cadssl_advanced_headers_options[' . esc_attr($id) . ']">';
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
        $options = get_option('cadssl_advanced_headers_options', array());
        $id = $args['id'];
        $value = isset($options[$id]) ? $options[$id] : (isset($args['default']) ? $args['default'] : '');
        
        echo '<textarea id="cadssl_advanced_headers_options_' . esc_attr($id) . '" name="cadssl_advanced_headers_options[' . esc_attr($id) . ']" rows="4" style="width:100%;" placeholder="' . esc_attr($args['placeholder']) . '">' . esc_textarea($value) . '</textarea>';
        echo '<p class="description">' . esc_html($args['description']) . '</p>';
    }
    
    /**
     * Display advanced headers settings page
     */
    public function display_headers_page() {
        ?>
        <div class="wrap">
            <h1><?php _e('Advanced Security Headers', 'cadssl'); ?></h1>
            
            <div class="notice notice-info">
                <p>
                    <?php _e('Security headers are HTTP response headers that define security policies for your website. They help prevent common web vulnerabilities like XSS, clickjacking, and more.', 'cadssl'); ?>
                </p>
                <p>
                    <?php _e('These settings follow OWASP Security Headers Project recommendations.', 'cadssl'); ?>
                    <a href="https://owasp.org/www-project-secure-headers/" target="_blank"><?php _e('Learn more', 'cadssl'); ?></a>
                </p>
            </div>
            
            <form method="post" action="options.php">
                <?php
                settings_fields('cadssl_advanced_headers_options');
                do_settings_sections('cadssl-advanced-headers');
                submit_button();
                ?>
            </form>
            
            <div class="card">
                <h2><?php _e('Test Your Security Headers', 'cadssl'); ?></h2>
                <p><?php _e('After configuring your security headers, use these tools to validate them:', 'cadssl'); ?></p>
                <ul>
                    <li><a href="https://securityheaders.com/" target="_blank">SecurityHeaders.com</a></li>
                    <li><a href="https://observatory.mozilla.org/" target="_blank">Mozilla Observatory</a></li>
                </ul>
            </div>
        </div>
        <?php
    }
    
    /**
     * Apply advanced security headers
     */
    public function apply_advanced_headers() {
        $options = get_option('cadssl_advanced_headers_options', array());
        
        // Content-Security-Policy
        if (isset($options['enable_csp']) && $options['enable_csp'] && !empty($options['csp_policy'])) {
            $csp_mode = isset($options['csp_mode']) ? $options['csp_mode'] : 'enforce';
            $header_name = ($csp_mode === 'report-only') ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
            header("$header_name: {$options['csp_policy']}");
        }
        
        // X-XSS-Protection
        if (isset($options['enable_xss_protection']) && $options['enable_xss_protection']) {
            header('X-XSS-Protection: 1; mode=block');
        }
        
        // X-Content-Type-Options
        if (isset($options['enable_content_type_options']) && $options['enable_content_type_options']) {
            header('X-Content-Type-Options: nosniff');
        }
        
        // X-Frame-Options
        if (isset($options['enable_frame_options']) && $options['enable_frame_options']) {
            $frame_value = isset($options['frame_options_value']) ? $options['frame_options_value'] : 'SAMEORIGIN';
            header("X-Frame-Options: $frame_value");
        }
        
        // Referrer-Policy
        if (isset($options['enable_referrer_policy']) && $options['enable_referrer_policy']) {
            $referrer_value = isset($options['referrer_policy_value']) ? $options['referrer_policy_value'] : 'strict-origin-when-cross-origin';
            header("Referrer-Policy: $referrer_value");
        }
        
        // Permissions-Policy
        if (isset($options['enable_permissions_policy']) && $options['enable_permissions_policy'] && !empty($options['permissions_policy_value'])) {
            header("Permissions-Policy: {$options['permissions_policy_value']}");
        }
        
        // Cross-Origin-Embedder-Policy
        if (isset($options['enable_coep']) && $options['enable_coep']) {
            $coep_value = isset($options['coep_value']) ? $options['coep_value'] : 'require-corp';
            header("Cross-Origin-Embedder-Policy: $coep_value");
        }
        
        // Cross-Origin-Opener-Policy
        if (isset($options['enable_coop']) && $options['enable_coop']) {
            $coop_value = isset($options['coop_value']) ? $options['coop_value'] : 'same-origin';
            header("Cross-Origin-Opener-Policy: $coop_value");
        }
        
        // Cross-Origin-Resource-Policy
        if (isset($options['enable_corp']) && $options['enable_corp']) {
            $corp_value = isset($options['corp_value']) ? $options['corp_value'] : 'same-origin';
            header("Cross-Origin-Resource-Policy: $corp_value");
        }
    }
    
    /**
     * Add Clear-Site-Data header on logout
     */
    public function clear_site_data_on_logout() {
        $options = get_option('cadssl_advanced_headers_options', array());
        if (isset($options['enable_clear_site_data']) && $options['enable_clear_site_data']) {
            header('Clear-Site-Data: "cache", "cookies", "storage", "executionContexts"');
        }
    }
}
