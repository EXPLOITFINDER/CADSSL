<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Two-Factor Authentication Class
 * Implements additional security layer for WordPress logins
 */
class CADSSL_Two_Factor {
    /**
     * Two-factor auth options
     * @var array
     */
    private $options = array();
    
    /**
     * Initialize two-factor authentication
     */
    public function init() {
        // Load options
        $this->options = get_option('cadssl_2fa_options', array(
            'enabled' => false,
            'enforce_admin' => false,
            'available_methods' => array('email'),
            'default_method' => 'email',
            'code_expiration' => 10, // minutes
            'enforce_roles' => array('administrator'),
            'remember_device' => true,
            'remember_duration' => 30, // days
            'disable_2fa_recovery' => false,
        ));
        
        // Only register hooks if 2FA is enabled
        if ($this->is_enabled()) {
            // Add authentication hooks
            add_action('wp_authenticate_user', array($this, 'authenticate_user_check'), 10, 2);
            add_filter('authenticate', array($this, 'authenticate_filter'), 50, 3);
            
            // Handle custom login form for 2FA
            add_action('login_form_validate_2fa', array($this, 'validate_2fa_code'));
            add_action('login_form_backup_2fa', array($this, 'validate_backup_code'));
            
            // Handle user profile settings
            add_action('show_user_profile', array($this, 'user_two_factor_options'));
            add_action('edit_user_profile', array($this, 'user_two_factor_options')); 
            add_action('personal_options_update', array($this, 'save_user_two_factor_options'));
            add_action('edit_user_profile_update', array($this, 'save_user_two_factor_options'));
            
            // Admin settings page
            add_action('admin_menu', array($this, 'add_submenu'), 21);
            add_action('admin_enqueue_scripts', array($this, 'enqueue_scripts'));
            
            // AJAX handlers
            add_action('wp_ajax_cadssl_generate_backup_codes', array($this, 'ajax_generate_backup_codes'));
            add_action('wp_ajax_cadssl_send_test_code', array($this, 'ajax_send_test_code'));
            add_action('wp_ajax_cadssl_verify_test_code', array($this, 'ajax_verify_test_code'));
            add_action('wp_ajax_cadssl_reset_user_2fa', array($this, 'ajax_reset_user_2fa'));
            
            // Device cookie handling
            add_action('wp_login', array($this, 'set_remember_cookie'), 10, 2);
        }
    }
    
    /**
     * Check if two-factor authentication is enabled
     * 
     * @return bool Whether 2FA is enabled
     */
    public function is_enabled() {
        return isset($this->options['enabled']) && $this->options['enabled'];
    }
    
    /**
     * Check if user requires 2FA
     * 
     * @param WP_User $user The user to check
     * @return bool Whether user requires 2FA
     */
    public function user_requires_2fa($user) {
        if (!$this->is_enabled()) {
            return false;
        }
        
        // Check if user has 2FA enabled
        $user_2fa = get_user_meta($user->ID, 'cadssl_2fa_enabled', true);
        
        // If admin enforcement is enabled, check user roles
        if (isset($this->options['enforce_admin']) && $this->options['enforce_admin']) {
            if (isset($this->options['enforce_roles']) && is_array($this->options['enforce_roles'])) {
                foreach ($this->options['enforce_roles'] as $role) {
                    if (in_array($role, $user->roles)) {
                        return true;
                    }
                }
            }
        }
        
        // Return user's 2FA preference
        return $user_2fa === '1';
    }
    
    /**
     * Handle user authentication check
     * 
     * @param WP_User|WP_Error $user User object or error
     * @param string $password User password
     * @return WP_User|WP_Error User object or error
     */
    public function authenticate_user_check($user, $password) {
        if (is_wp_error($user)) {
            return $user;
        }
        
        // Check if user requires 2FA
        if (!$this->user_requires_2fa($user)) {
            return $user;
        }
        
        // Check if user is already in 2FA process
        if (isset($_POST['cadssl_2fa_code'])) {
            return $user;
        }
        
        // Check if remember device is enabled and user has a valid cookie
        if ($this->is_remember_device_enabled() && $this->verify_remember_cookie($user->ID)) {
            return $user;
        }
        
        // Generate and store auth code
        $auth_code = $this->generate_auth_code($user->ID);
        if (!$auth_code) {
            return new WP_Error('2fa_error', __('Error generating authentication code.', 'cadssl'));
        }
        
        // Send auth code to user
        $method = $this->get_user_preferred_method($user->ID);
        $sent = $this->send_auth_code($user, $auth_code, $method);
        
        if (!$sent) {
            return new WP_Error('2fa_error', __('Error sending authentication code.', 'cadssl'));
        }
        
        // Create a session to remember the user between steps
        $session_token = wp_generate_password(64, false, false);
        WP_Session_Tokens::get_instance($user->ID)->create($session_token);
        
        // Store user ID and token in a cookie for the second step
        setcookie('cadssl_2fa_user', $user->ID, time() + 600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
        setcookie('cadssl_2fa_token', $session_token, time() + 600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
        
        // Redirect to 2FA code entry page
        wp_safe_redirect(add_query_arg('action', 'cadssl_2fa', wp_login_url()));
        exit;
    }
    
    /**
     * Filter authenticate process to add 2FA step
     * 
     * @param WP_User|null $user User object or null
     * @param string $username Username
     * @param string $password Password
     * @return WP_User|WP_Error User object or error
     */
    public function authenticate_filter($user, $username, $password) {
        if (!is_wp_error($user) && $user) {
            // If we're on the 2FA page, verify the code
            if (isset($_POST['cadssl_2fa_code']) && isset($_COOKIE['cadssl_2fa_user'])) {
                $user_id = intval($_COOKIE['cadssl_2fa_user']);
                $session_token = isset($_COOKIE['cadssl_2fa_token']) ? $_COOKIE['cadssl_2fa_token'] : '';
                
                // Verify the session token
                if (!$session_token || !WP_Session_Tokens::get_instance($user_id)->verify($session_token)) {
                    return new WP_Error('invalid_session', __('Invalid session. Please try logging in again.', 'cadssl'));
                }
                
                // Check if the user in cookie matches the authenticated user
                if ($user_id !== $user->ID) {
                    return new WP_Error('invalid_user', __('Invalid user. Please try logging in again.', 'cadssl'));
                }
                
                // Verify the 2FA code
                $code = sanitize_text_field($_POST['cadssl_2fa_code']);
                if ($this->verify_auth_code($user->ID, $code)) {
                    // Clear cookies
                    setcookie('cadssl_2fa_user', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
                    setcookie('cadssl_2fa_token', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
                    
                    // Set remember device cookie if requested
                    if (isset($_POST['cadssl_remember_device']) && $this->is_remember_device_enabled()) {
                        $this->set_remember_cookie($user);
                    }
                    
                    // Return the user to complete login
                    return $user;
                } else {
                    return new WP_Error('invalid_code', __('Invalid verification code. Please try again.', 'cadssl'));
                }
            }
        }
        
        return $user;
    }
    
    /**
     * Handle 2FA code validation form
     */
    public function validate_2fa_code() {
        if (!isset($_COOKIE['cadssl_2fa_user']) || !isset($_COOKIE['cadssl_2fa_token'])) {
            wp_safe_redirect(wp_login_url());
            exit;
        }
        
        $user_id = intval($_COOKIE['cadssl_2fa_user']);
        $user = get_user_by('id', $user_id);
        
        if (!$user) {
            wp_safe_redirect(wp_login_url());
            exit;
        }
        
        login_header(__('Two-Factor Authentication', 'cadssl'), '', new WP_Error());
        
        $method = $this->get_user_preferred_method($user_id);
        $method_label = $this->get_method_label($method);
        $redirect_to = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : admin_url();
        
        // Get code expiration time
        $expiration_time = get_user_meta($user_id, 'cadssl_2fa_code_expiration', true);
        $minutes_remaining = 0;
        if ($expiration_time) {
            $minutes_remaining = max(0, ceil(($expiration_time - time()) / 60));
        }
        
        ?>
        <style>
            .cadssl-2fa-container {
                max-width: 400px;
                margin: 20px auto;
                text-align: center;
            }
            .cadssl-2fa-code {
                font-size: 24px;
                letter-spacing: 5px;
                text-align: center;
            }
            .cadssl-2fa-remember {
                margin-top: 20px;
            }
            .cadssl-2fa-resend {
                margin-top: 20px;
            }
            .cadssl-2fa-backup {
                margin-top: 20px;
                font-size: 0.9em;
            }
        </style>
        <form name="cadssl_2fa_form" id="cadssl_2fa_form" action="<?php echo esc_url(site_url('wp-login.php?action=cadssl_2fa', 'login_post')); ?>" method="post">
            <div class="cadssl-2fa-container">
                <p>
                    <?php 
                    printf(
                        __('A verification code has been sent to your %s. Please enter it below to continue.', 'cadssl'),
                        $method_label
                    ); 
                    ?>
                </p>
                
                <p>
                    <label for="cadssl_2fa_code"><?php _e('Verification Code', 'cadssl'); ?></label>
                    <br>
                    <input type="text" name="cadssl_2fa_code" id="cadssl_2fa_code" class="input cadssl-2fa-code" autocomplete="off" value="" size="6" maxlength="6" pattern="[0-9]*" inputmode="numeric" autofocus />
                </p>
                
                <?php if ($minutes_remaining > 0): ?>
                <p>
                    <?php printf(__('Code expires in %d minutes.', 'cadssl'), $minutes_remaining); ?>
                </p>
                <?php endif; ?>
                
                <?php if ($this->is_remember_device_enabled()): ?>
                <p class="cadssl-2fa-remember">
                    <input type="checkbox" name="cadssl_remember_device" id="cadssl_remember_device" value="1">
                    <label for="cadssl_remember_device">
                        <?php 
                        printf(
                            __('Remember this device for %d days', 'cadssl'), 
                            $this->options['remember_duration']
                        ); 
                        ?>
                    </label>
                </p>
                <?php endif; ?>
                
                <p>
                    <button type="submit" name="submit" class="button button-primary button-large">
                        <?php _e('Verify Code', 'cadssl'); ?>
                    </button>
                </p>
                
                <p class="cadssl-2fa-resend">
                    <a href="<?php echo esc_url(add_query_arg('resend', '1')); ?>">
                        <?php _e('Resend code', 'cadssl'); ?>
                    </a>
                </p>
                
                <?php if (!isset($this->options['disable_2fa_recovery']) || !$this->options['disable_2fa_recovery']): ?>
                <p class="cadssl-2fa-backup">
                    <a href="<?php echo esc_url(add_query_arg('action', 'backup_2fa', wp_login_url())); ?>">
                        <?php _e('Use a backup code', 'cadssl'); ?>
                    </a>
                </p>
                <?php endif; ?>
                
                <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to); ?>" />
                <input type="hidden" name="testcookie" value="1" />
            </div>
            <?php wp_nonce_field('cadssl_2fa_nonce'); ?>
        </form>
        
        <script>
        // Automatically submit when 6 digits are entered
        document.getElementById('cadssl_2fa_code').addEventListener('input', function() {
            if (this.value.length === 6) {
                document.getElementById('cadssl_2fa_form').submit();
            }
        });
        </script>
        <?php
        
        login_footer();
        exit;
    }
    
    /**
     * Handle backup code validation
     */
    public function validate_backup_code() {
        if (!isset($_COOKIE['cadssl_2fa_user']) || !isset($_COOKIE['cadssl_2fa_token'])) {
            wp_safe_redirect(wp_login_url());
            exit;
        }
        
        // Check if backup codes are disabled
        if (isset($this->options['disable_2fa_recovery']) && $this->options['disable_2fa_recovery']) {
            wp_safe_redirect(wp_login_url());
            exit;
        }
        
        $user_id = intval($_COOKIE['cadssl_2fa_user']);
        $user = get_user_by('id', $user_id);
        
        if (!$user) {
            wp_safe_redirect(wp_login_url());
            exit;
        }
        
        login_header(__('Two-Factor Authentication Backup Code', 'cadssl'), '', new WP_Error());
        
        $redirect_to = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : admin_url();
        ?>
        <style>
            .cadssl-2fa-container {
                max-width: 400px;
                margin: 20px auto;
                text-align: center;
            }
            .cadssl-2fa-backup-code {
                font-size: 20px;
                letter-spacing: 2px;
                text-align: center;
            }
        </style>
        <form name="cadssl_backup_form" id="cadssl_backup_form" action="<?php echo esc_url(site_url('wp-login.php?action=backup_2fa', 'login_post')); ?>" method="post">
            <div class="cadssl-2fa-container">
                <p>
                    <?php _e('Enter a backup code to sign in to your account.', 'cadssl'); ?>
                </p>
                
                <p>
                    <label for="cadssl_backup_code"><?php _e('Backup Code', 'cadssl'); ?></label>
                    <br>
                    <input type="text" name="cadssl_backup_code" id="cadssl_backup_code" class="input cadssl-2fa-backup-code" autocomplete="off" value="" size="10" maxlength="10" autofocus />
                </p>
                
                <p>
                    <button type="submit" name="submit" class="button button-primary button-large">
                        <?php _e('Verify Code', 'cadssl'); ?>
                    </button>
                </p>
                
                <p>
                    <a href="<?php echo esc_url(add_query_arg('action', 'cadssl_2fa', wp_login_url())); ?>">
                        <?php _e('Back to verification code', 'cadssl'); ?>
                    </a>
                </p>
                
                <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to); ?>" />
                <input type="hidden" name="testcookie" value="1" />
            </div>
            <?php wp_nonce_field('cadssl_backup_nonce'); ?>
        </form>
        <?php
        
        login_footer();
        exit;
    }
    
    /**
     * Add submenu for 2FA settings
     */
    public function add_submenu() {
        add_submenu_page(
            'cadssl-settings',
            __('Two-Factor Authentication', 'cadssl'),
            __('Two-Factor Auth', 'cadssl'),
            'manage_options',
            'cadssl-two-factor',
            array($this, 'render_settings_page')
        );
    }
    
    /**
     * Render 2FA settings page
     */
    public function render_settings_page() {
        // Save settings
        if (isset($_POST['submit']) && check_admin_referer('cadssl_2fa_settings')) {
            $this->options['enabled'] = isset($_POST['enabled']) ? true : false;
            $this->options['enforce_admin'] = isset($_POST['enforce_admin']) ? true : false;
            $this->options['remember_device'] = isset($_POST['remember_device']) ? true : false;
            $this->options['remember_duration'] = absint($_POST['remember_duration']);
            $this->options['code_expiration'] = absint($_POST['code_expiration']);
            $this->options['disable_2fa_recovery'] = isset($_POST['disable_2fa_recovery']) ? true : false;
            
            // Sanitize available methods
            $this->options['available_methods'] = array();
            if (isset($_POST['available_methods']) && is_array($_POST['available_methods'])) {
                $valid_methods = array('email');
                foreach ($_POST['available_methods'] as $method) {
                    if (in_array($method, $valid_methods)) {
                        $this->options['available_methods'][] = $method;
                    }
                }
            }
            
            // Default to email if no methods selected
            if (empty($this->options['available_methods'])) {
                $this->options['available_methods'] = array('email');
            }
            
            // Set default method
            $this->options['default_method'] = in_array($_POST['default_method'], $this->options['available_methods']) ? 
                $_POST['default_method'] : $this->options['available_methods'][0];
            
            // Save enforced roles
            $this->options['enforce_roles'] = array();
            if (isset($_POST['enforce_roles']) && is_array($_POST['enforce_roles'])) {
                $this->options['enforce_roles'] = array_map('sanitize_text_field', $_POST['enforce_roles']);
            }
            
            // Save options
            update_option('cadssl_2fa_options', $this->options);
            
            echo '<div class="notice notice-success"><p>' . __('Settings saved successfully.', 'cadssl') . '</p></div>';
        }
        
        // Get all roles
        $roles = wp_roles()->get_names();
        
        ?>
        <div class="wrap">
            <h1><?php _e('Two-Factor Authentication Settings', 'cadssl'); ?></h1>
            
            <form method="post" action="">
                <?php wp_nonce_field('cadssl_2fa_settings'); ?>
                
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><?php _e('Enable Two-Factor Authentication', 'cadssl'); ?></th>
                        <td>
                            <label for="enabled">
                                <input name="enabled" type="checkbox" id="enabled" value="1" <?php checked($this->options['enabled']); ?>>
                                <?php _e('Enable two-factor authentication for this site', 'cadssl'); ?>
                            </label>
                            <p class="description"><?php _e('This will allow users to enable 2FA for their accounts.', 'cadssl'); ?></p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row"><?php _e('Available Methods', 'cadssl'); ?></th>
                        <td>
                            <fieldset>
                                <legend class="screen-reader-text"><span><?php _e('Available Methods', 'cadssl'); ?></span></legend>
                                <label for="available_methods_email">
                                    <input name="available_methods[]" type="checkbox" id="available_methods_email" value="email" 
                                        <?php checked(in_array('email', $this->options['available_methods'])); ?>>
                                    <?php _e('Email Authentication', 'cadssl'); ?>
                                </label><br>
                                
                                <p class="description">
                                    <?php _e('Additional methods (SMS, Authenticator app) available in the premium version.', 'cadssl'); ?>
                                </p>
                            </fieldset>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row"><?php _e('Default Method', 'cadssl'); ?></th>
                        <td>
                            <select name="default_method" id="default_method">
                                <?php if (in_array('email', $this->options['available_methods'])): ?>
                                <option value="email" <?php selected($this->options['default_method'], 'email'); ?>><?php _e('Email', 'cadssl'); ?></option>
                                <?php endif; ?>
                            </select>
                            <p class="description"><?php _e('Default authentication method for new users.', 'cadssl'); ?></p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row"><?php _e('Enforce for Roles', 'cadssl'); ?></th>
                        <td>
                            <fieldset>
                                <legend class="screen-reader-text"><span><?php _e('Enforce for Roles', 'cadssl'); ?></span></legend>
                                <label for="enforce_admin">
                                    <input name="enforce_admin" type="checkbox" id="enforce_admin" value="1" 
                                        <?php checked($this->options['enforce_admin']); ?>
                                        onchange="document.getElementById('enforce_roles_section').style.display = this.checked ? 'block' : 'none';">
                                    <?php _e('Enforce 2FA for specific user roles', 'cadssl'); ?>
                                </label>
                                
                                <div id="enforce_roles_section" style="display: <?php echo $this->options['enforce_admin'] ? 'block' : 'none'; ?>; margin-top: 10px; padding: 10px; background: #f8f8f8; border-radius: 3px;">
                                    <?php foreach ($roles as $role => $name): ?>
                                    <label style="display: block; margin-bottom: 5px;">
                                        <input name="enforce_roles[]" type="checkbox" value="<?php echo esc_attr($role); ?>" 
                                            <?php checked(in_array($role, $this->options['enforce_roles'])); ?>>
                                        <?php echo esc_html($name); ?>
                                    </label>
                                    <?php endforeach; ?>
                                </div>
                            </fieldset>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row"><?php _e('Remember Device', 'cadssl'); ?></th>
                        <td>
                            <label for="remember_device">
                                <input name="remember_device" type="checkbox" id="remember_device" value="1" 
                                    <?php checked($this->options['remember_device']); ?>
                                    onchange="document.getElementById('remember_duration_row').style.display = this.checked ? 'table-row' : 'none';">
                                <?php _e('Allow users to remember their device', 'cadssl'); ?>
                            </label>
                            <p class="description"><?php _e('Users can choose to skip 2FA on devices they trust.', 'cadssl'); ?></p>
                        </td>
                    </tr>
                    
                    <tr id="remember_duration_row" style="display: <?php echo $this->options['remember_device'] ? 'table-row' : 'none'; ?>;">
                        <th scope="row"><?php _e('Remember Duration', 'cadssl'); ?></th>
                        <td>
                            <input name="remember_duration" type="number" id="remember_duration" min="1" max="365" 
                                value="<?php echo esc_attr($this->options['remember_duration']); ?>">
                            <p class="description"><?php _e('Number of days to remember a trusted device.', 'cadssl'); ?></p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row"><?php _e('Code Expiration', 'cadssl'); ?></th>
                        <td>
                            <input name="code_expiration" type="number" id="code_expiration" min="1" max="60" 
                                value="<?php echo esc_attr($this->options['code_expiration']); ?>">
                            <p class="description"><?php _e('Minutes until a verification code expires.', 'cadssl'); ?></p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row"><?php _e('Disable Backup Codes', 'cadssl'); ?></th>
                        <td>
                            <label for="disable_2fa_recovery">
                                <input name="disable_2fa_recovery" type="checkbox" id="disable_2fa_recovery" value="1" 
                                    <?php checked($this->options['disable_2fa_recovery']); ?>>
                                <?php _e('Disable backup code recovery method', 'cadssl'); ?>
                            </label>
                            <p class="description"><?php _e('If enabled, users won\'t be able to use backup codes to sign in.', 'cadssl'); ?></p>
                        </td>
                    </tr>
                </table>
                
                <p class="submit">
                    <input type="submit" name="submit" id="submit" class="button button-primary" value="<?php _e('Save Changes', 'cadssl'); ?>">
                </p>
            </form>
        </div>
        <?php
    }
    
    /**
     * User profile two-factor settings
     * 
     * @param WP_User $user User object
     */
    public function user_two_factor_options($user) {
        // Only show if 2FA is enabled globally
        if (!$this->is_enabled()) {
            return;
        }
        
        // Don't show for other users unless current user is admin
        if (!current_user_can('edit_user', $user->ID) && get_current_user_id() !== $user->ID) {
            return;
        }
        
        // Get user's 2FA settings
        $user_2fa_enabled = get_user_meta($user->ID, 'cadssl_2fa_enabled', true) === '1';
        $user_2fa_method = get_user_meta($user->ID, 'cadssl_2fa_method', true);
        
        // Check if 2FA is enforced for this user
        $is_enforced = false;
        if ($this->options['enforce_admin']) {
            foreach ($this->options['enforce_roles'] as $role) {
                if (in_array($role, $user->roles)) {
                    $is_enforced = true;
                    break;
                }
            }
        }
        
        // If not set, use default method
        if (!$user_2fa_method) {
            $user_2fa_method = $this->options['default_method'];
        }
        
        ?>
        <h2><?php _e('Two-Factor Authentication', 'cadssl'); ?></h2>
        <table class="form-table">
            <tr>
                <th>
                    <label for="cadssl_2fa_enabled"><?php _e('Enable Two-Factor Authentication', 'cadssl'); ?></label>
                </th>
                <td>
                    <input type="checkbox" name="cadssl_2fa_enabled" id="cadssl_2fa_enabled" value="1" 
                        <?php checked($user_2fa_enabled); ?> 
                        <?php disabled($is_enforced); ?>>
                    <span class="description">
                        <?php 
                        if ($is_enforced) {
                            _e('Two-factor authentication is required for your role.', 'cadssl'); 
                        } else {
                            _e('Protect your account with two-factor authentication.', 'cadssl'); 
                        }
                        ?>
                    </span>
                </td>
            </tr>
            
            <tr class="cadssl-2fa-method" style="display: <?php echo ($user_2fa_enabled || $is_enforced) ? 'table-row' : 'none'; ?>;">
                <th>
                    <label for="cadssl_2fa_method"><?php _e('Authentication Method', 'cadssl'); ?></label>
                </th>
                <td>
                    <select name="cadssl_2fa_method" id="cadssl_2fa_method">
                        <?php if (in_array('email', $this->options['available_methods'])): ?>
                        <option value="email" <?php selected($user_2fa_method, 'email'); ?>><?php _e('Email Authentication', 'cadssl'); ?></option>
                        <?php endif; ?>
                    </select>
                    <p class="description"><?php _e('How you\'ll receive your verification code.', 'cadssl'); ?></p>
                </td>
            </tr>
            
            <tr class="cadssl-2fa-email" style="display: <?php echo (($user_2fa_enabled || $is_enforced) && $user_2fa_method === 'email') ? 'table-row' : 'none'; ?>;">
                <th>
                    <label><?php _e('Email Address', 'cadssl'); ?></label>
                </th>
                <td>
                    <p><?php echo esc_html($user->user_email); ?></p>
                    <p class="description"><?php _e('Verification codes will be sent to this email address.', 'cadssl'); ?></p>
                    <p>
                        <button type="button" class="button" id="cadssl_test_email">
                            <?php _e('Send Test Code', 'cadssl'); ?>
                        </button>
                        <span id="cadssl_email_result"></span>
                    </p>
                </td>
            </tr>
            
            <tr class="cadssl-2fa-backup-codes" style="display: <?php echo ($user_2fa_enabled || $is_enforced) ? 'table-row' : 'none'; ?>;">
                <th>
                    <label><?php _e('Backup Codes', 'cadssl'); ?></label>
                </th>
                <td>
                    <p>
                        <button type="button" class="button" id="cadssl_generate_backup">
                            <?php _e('Generate Backup Codes', 'cadssl'); ?>
                        </button>
                    </p>
                    <div id="cadssl_backup_codes" style="display: none;">
                        <p class="description"><?php _e('Keep these backup codes somewhere safe but accessible.', 'cadssl'); ?></p>
                        <ul class="cadssl-backup-code-list" style="font-family: monospace;"></ul>
                        <p><button type="button" class="button" id="cadssl_print_codes"><?php _e('Print Codes', 'cadssl'); ?></button></p>
                    </div>
                </td>
            </tr>
        </table>
        
        <script type="text/javascript">
        jQuery(document).ready(function($) {
            // Toggle 2FA method options based on enabled checkbox
            $('#cadssl_2fa_enabled').on('change', function() {
                if ($(this).is(':checked')) {
                    $('.cadssl-2fa-method').show();
                    // Also show the appropriate method details
                    showMethodFields();
                } else {
                    $('.cadssl-2fa-method').hide();
                    $('.cadssl-2fa-email').hide();
                    $('.cadssl-2fa-backup-codes').hide();
                }
            });
            
            // Toggle method-specific fields
            $('#cadssl_2fa_method').on('change', function() {
                showMethodFields();
            });
            
            function showMethodFields() {
                var method = $('#cadssl_2fa_method').val();
                $('.cadssl-2fa-email').hide();
                
                if (method === 'email') {
                    $('.cadssl-2fa-email').show();
                }
                
                // Always show backup codes section if 2FA is enabled
                if ($('#cadssl_2fa_enabled').is(':checked')) {
                    $('.cadssl-2fa-backup-codes').show();
                }
            }
            
            // Handle test email button
            $('#cadssl_test_email').on('click', function() {
                var $button = $(this);
                var $result = $('#cadssl_email_result');
                
                $button.prop('disabled', true);
                $result.text('<?php _e('Sending...', 'cadssl'); ?>');
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'cadssl_send_test_code',
                        user_id: <?php echo $user->ID; ?>,
                        _wpnonce: '<?php echo wp_create_nonce('cadssl_test_code'); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            $result.html('<span style="color:green">' + response.data.message + '</span>');
                            
                            // Show verification form
                            var verifyHtml = '<div id="cadssl_verify_container" style="margin-top:10px;">' +
                                '<input type="text" id="cadssl_verify_code" placeholder="<?php _e('Enter code', 'cadssl'); ?>" style="width:100px;">' +
                                '<button type="button" class="button" id="cadssl_verify_button"><?php _e('Verify', 'cadssl'); ?></button>' +
                                '<span id="cadssl_verify_result"></span>' +
                                '</div>';
                            $result.after(verifyHtml);
                            
                            // Handle verify button
                            $('#cadssl_verify_button').on('click', function() {
                                var $verifyButton = $(this);
                                var $verifyResult = $('#cadssl_verify_result');
                                var code = $('#cadssl_verify_code').val();
                                
                                if (!code) {
                                    $verifyResult.html('<span style="color:red"><?php _e('Please enter the code', 'cadssl'); ?></span>');
                                    return;
                                }
                                
                                $verifyButton.prop('disabled', true);
                                $verifyResult.text('<?php _e('Verifying...', 'cadssl'); ?>');
                                
                                $.ajax({
                                    url: ajaxurl,
                                    type: 'POST',
                                    data: {
                                        action: 'cadssl_verify_test_code',
                                        user_id: <?php echo $user->ID; ?>,
                                        code: code,
                                        _wpnonce: '<?php echo wp_create_nonce('cadssl_verify_test_code'); ?>'
                                    },
                                    success: function(response) {
                                        if (response.success) {
                                            $verifyResult.html('<span style="color:green">' + response.data.message + '</span>');
                                        } else {
                                            $verifyResult.html('<span style="color:red">' + response.data + '</span>');
                                            $verifyButton.prop('disabled', false);
                                        }
                                    },
                                    error: function() {
                                        $verifyResult.html('<span style="color:red"><?php _e('Verification failed', 'cadssl'); ?></span>');
                                        $verifyButton.prop('disabled', false);
                                    }
                                });
                            });
                        } else {
                            $result.html('<span style="color:red">' + response.data + '</span>');
                            $button.prop('disabled', false);
                        }
                    },
                    error: function() {
                        $result.html('<span style="color:red"><?php _e('Failed to send test code', 'cadssl'); ?></span>');
                        $button.prop('disabled', false);
                    }
                });
            });
            
            // Handle generate backup codes button
            $('#cadssl_generate_backup').on('click', function() {
                var $button = $(this);
                var $codesList = $('.cadssl-backup-code-list');
                
                if (confirm('<?php _e('Generate new backup codes? This will invalidate any existing backup codes.', 'cadssl'); ?>')) {
                    $button.prop('disabled', true);
                    $button.text('<?php _e('Generating...', 'cadssl'); ?>');
                    
                    $.ajax({
                        url: ajaxurl,
                        type: 'POST',
                        data: {
                            action: 'cadssl_generate_backup_codes',
                            user_id: <?php echo $user->ID; ?>,
                            _wpnonce: '<?php echo wp_create_nonce('cadssl_generate_backup_codes'); ?>'
                        },
                        success: function(response) {
                            if (response.success) {
                                $codesList.empty();
                                $.each(response.data.codes, function(index, code) {
                                    $codesList.append('<li>' + code + '</li>');
                                });
                                $('#cadssl_backup_codes').show();
                            } else {
                                alert(response.data);
                            }
                            $button.prop('disabled', false);
                            $button.text('<?php _e('Generate Backup Codes', 'cadssl'); ?>');
                        },
                        error: function() {
                            alert('<?php _e('Failed to generate backup codes', 'cadssl'); ?>');
                            $button.prop('disabled', false);
                            $button.text('<?php _e('Generate Backup Codes', 'cadssl'); ?>');
                        }
                    });
                }
            });
            
            // Handle print codes button
            $('#cadssl_print_codes').on('click', function() {
                var content = '<html><head><title><?php _e('Backup Codes', 'cadssl'); ?></title>' +
                    '<style>body{font-family:monospace;}</style></head><body>' +
                    '<h1><?php _e('Backup Codes', 'cadssl'); ?></h1>' +
                    '<p><?php _e('Keep these backup codes somewhere safe but accessible.', 'cadssl'); ?></p>' +
                    '<ul>';
                
                $('.cadssl-backup-code-list li').each(function() {
                    content += '<li>' + $(this).text() + '</li>';
                });
                
                content += '</ul></body></html>';
                
                var win = window.open('', '_blank');
                win.document.write(content);
                win.document.close();
                win.print();
            });
        });
        </script>
        <?php
    }
    
    /**
     * Save user two-factor settings
     * 
     * @param int $user_id User ID
     * @return void
     */
    public function save_user_two_factor_options($user_id) {
        // Only admins or the user themselves can update
        if (!current_user_can('edit_user', $user_id) && get_current_user_id() !== $user_id) {
            return;
        }
        
        // Save 2FA enabled status
        $is_enforced = $this->is_user_role_enforced($user_id);
        
        if (!$is_enforced) {
            $enabled = isset($_POST['cadssl_2fa_enabled']) ? '1' : '0';
            update_user_meta($user_id, 'cadssl_2fa_enabled', $enabled);
        }
        
        // Save 2FA method
        if (isset($_POST['cadssl_2fa_method'])) {
            $method = sanitize_text_field($_POST['cadssl_2fa_method']);
            if (in_array($method, $this->options['available_methods'])) {
                update_user_meta($user_id, 'cadssl_2fa_method', $method);
            }
        }
    }
    
    /**
     * Check if 2FA is enforced for user's role
     * 
     * @param int $user_id User ID
     * @return bool Whether 2FA is enforced
     */
    private function is_user_role_enforced($user_id) {
        if (!isset($this->options['enforce_admin']) || !$this->options['enforce_admin']) {
            return false;
        }
        
        $user = get_user_by('id', $user_id);
        if (!$user) {
            return false;
        }
        
        foreach ($this->options['enforce_roles'] as $role) {
            if (in_array($role, $user->roles)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Enqueue scripts for 2FA settings page
     * 
     * @param string $hook Current admin page
     */
    public function enqueue_scripts($hook) {
        if ($hook !== 'settings_page_cadssl-two-factor') {
            return;
        }
        
        wp_enqueue_style('cadssl-two-factor', CADSSL_URL . 'assets/css/two-factor.css', array(), CADSSL_VERSION);
        wp_enqueue_script('cadssl-two-factor', CADSSL_URL . 'assets/js/two-factor.js', array('jquery'), CADSSL_VERSION, true);
        
        wp_localize_script('cadssl-two-factor', 'cadssl_2fa', array(
            'nonce' => wp_create_nonce('cadssl_2fa_admin_nonce'),
            'reset_2fa_confirm' => __('Are you sure you want to reset 2FA for this user? They will need to set it up again.', 'cadssl')
        ));
    }
    
    /**
     * AJAX handler to generate backup codes
     */
    public function ajax_generate_backup_codes() {
        // Verify nonce
        check_ajax_referer('cadssl_generate_backup_codes', '_wpnonce');
        
        $user_id = isset($_POST['user_id']) ? absint($_POST['user_id']) : 0;
        
        // Only admins or the user themselves can generate codes
        if (!current_user_can('edit_user', $user_id) && get_current_user_id() !== $user_id) {
            wp_send_json_error(__('Permission denied', 'cadssl'));
            return;
        }
        
        // Generate 10 backup codes
        $backup_codes = array();
        for ($i = 0; $i < 10; $i++) {
            $backup_codes[] = $this->generate_backup_code();
        }
        
        // Hash the codes for storage
        $hashed_codes = array();
        foreach ($backup_codes as $code) {
            $hashed_codes[] = wp_hash_password($code);
        }
        
        // Store the hashed codes
        update_user_meta($user_id, 'cadssl_backup_codes', $hashed_codes);
        
        wp_send_json_success(array(
            'codes' => $backup_codes,
            'message' => __('Backup codes generated successfully', 'cadssl')
        ));
    }
    
    /**
     * AJAX handler to send test code
     */
    public function ajax_send_test_code() {
        // Verify nonce
        check_ajax_referer('cadssl_test_code', '_wpnonce');
        
        $user_id = isset($_POST['user_id']) ? absint($_POST['user_id']) : 0;
        
        // Only admins or the user themselves can test
        if (!current_user_can('edit_user', $user_id) && get_current_user_id() !== $user_id) {
            wp_send_json_error(__('Permission denied', 'cadssl'));
            return;
        }
        
        $user = get_user_by('id', $user_id);
        if (!$user) {
            wp_send_json_error(__('Invalid user', 'cadssl'));
            return;
        }
        
        // Generate and store test code
        $code = $this->generate_auth_code($user_id, true);
        
        // Send code to user's email
        $sent = $this->send_auth_code($user, $code, 'email', true);
        
        if ($sent) {
            wp_send_json_success(array(
                'message' => __('Test code sent successfully. Check your email.', 'cadssl')
            ));
        } else {
            wp_send_json_error(__('Failed to send test code', 'cadssl'));
        }
    }
    
    /**
     * AJAX handler to verify test code
     */
    public function ajax_verify_test_code() {
        // Verify nonce
        check_ajax_referer('cadssl_verify_test_code', '_wpnonce');
        
        $user_id = isset($_POST['user_id']) ? absint($_POST['user_id']) : 0;
        $code = isset($_POST['code']) ? sanitize_text_field($_POST['code']) : '';
        
        // Only admins or the user themselves can test
        if (!current_user_can('edit_user', $user_id) && get_current_user_id() !== $user_id) {
            wp_send_json_error(__('Permission denied', 'cadssl'));
            return;
        }
        
        // Verify the code
        $verified = $this->verify_auth_code($user_id, $code);
        
        if ($verified) {
            wp_send_json_success(array(
                'message' => __('Code verified successfully!', 'cadssl')
            ));
        } else {
            wp_send_json_error(__('Invalid code or code expired', 'cadssl'));
        }
    }
    
    /**
     * AJAX handler to reset user 2FA
     */
    public function ajax_reset_user_2fa() {
        // Verify nonce
        check_ajax_referer('cadssl_2fa_admin_nonce', 'nonce');
        
        // Only admins can reset other users' 2FA
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permission denied', 'cadssl'));
            return;
        }
        
        $user_id = isset($_POST['user_id']) ? absint($_POST['user_id']) : 0;
        
        if (!$user_id) {
            wp_send_json_error(__('Invalid user', 'cadssl'));
            return;
        }
        
        // Delete all 2FA related user meta
        delete_user_meta($user_id, 'cadssl_2fa_enabled');
        delete_user_meta($user_id, 'cadssl_2fa_method');
        delete_user_meta($user_id, 'cadssl_backup_codes');
        delete_user_meta($user_id, 'cadssl_2fa_secret');
        delete_user_meta($user_id, 'cadssl_2fa_code');
        delete_user_meta($user_id, 'cadssl_2fa_code_expiration');
        
        wp_send_json_success(array(
            'message' => __('Two-factor authentication settings have been reset', 'cadssl')
        ));
    }
    
    /**
     * Generate random backup code
     * 
     * @return string Backup code
     */
    private function generate_backup_code() {
        $chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $code = '';
        
        for ($i = 0; $i < 10; $i++) {
            $code .= $chars[rand(0, strlen($chars) - 1)];
        }
        
        return $code;
    }
    
    /**
     * Generate authentication code
     * 
     * @param int $user_id User ID
     * @param bool $is_test Whether this is a test code
     * @return string|bool Authentication code or false on failure
     */
    private function generate_auth_code($user_id, $is_test = false) {
        // Generate a 6-digit code
        $code = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
        
        // Get code expiration time
        $expiration_minutes = isset($this->options['code_expiration']) ? $this->options['code_expiration'] : 10;
        $expires = time() + ($expiration_minutes * 60);
        
        // Store code and expiration time in user meta
        update_user_meta($user_id, 'cadssl_2fa_code', $code);
        update_user_meta($user_id, 'cadssl_2fa_code_expiration', $expires);
        
        return $code;
    }
    
    /**
     * Verify authentication code
     * 
     * @param int $user_id User ID
     * @param string $code Authentication code to verify
     * @return bool Whether code is valid
     */
    private function verify_auth_code($user_id, $code) {
        // Get stored code and expiration
        $stored_code = get_user_meta($user_id, 'cadssl_2fa_code', true);
        $expires = get_user_meta($user_id, 'cadssl_2fa_code_expiration', true);
        
        // Check if code exists and hasn't expired
        if (!$stored_code || !$expires || time() > $expires) {
            return false;
        }
        
        // Check if codes match
        if ($code === $stored_code) {
            // Delete the code after successful verification
            delete_user_meta($user_id, 'cadssl_2fa_code');
            delete_user_meta($user_id, 'cadssl_2fa_code_expiration');
            
            return true;
        }
        
        return false;
    }
    
    /**
     * Verify backup code
     * 
     * @param int $user_id User ID
     * @param string $code Backup code to verify
     * @return bool Whether code is valid
     */
    private function verify_backup_code($user_id, $code) {
        // Get stored backup codes
        $backup_codes = get_user_meta($user_id, 'cadssl_backup_codes', true);
        
        if (!$backup_codes || !is_array($backup_codes)) {
            return false;
        }
        
        // Check each backup code
        foreach ($backup_codes as $key => $hashed_code) {
            if (wp_check_password($code, $hashed_code)) {
                // Remove used backup code
                unset($backup_codes[$key]);
                update_user_meta($user_id, 'cadssl_backup_codes', $backup_codes);
                
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Send authentication code to user
     * 
     * @param WP_User $user User object
     * @param string $code Authentication code
     * @param string $method Delivery method (email, sms)
     * @param bool $is_test Whether this is a test code
     * @return bool Whether code was sent successfully
     */
    private function send_auth_code($user, $code, $method = 'email', $is_test = false) {
        switch ($method) {
            case 'email':
                $subject = sprintf(__('[%s] Your Authentication Code', 'cadssl'), get_bloginfo('name'));
                
                if ($is_test) {
                    $message = sprintf(
                        __('Hello %s,

This is a TEST authentication code for CADSSL Security two-factor authentication.

Your authentication code is: %s

This code will expire in %d minutes.

If you did not request this code, please ignore this email.

Regards,
%s', 'cadssl'),
                        $user->display_name,
                        $code,
                        $this->options['code_expiration'],
                        get_bloginfo('name')
                    );
                } else {
                    $message = sprintf(
                        __('Hello %s,

Your authentication code for logging into %s is: %s

This code will expire in %d minutes.

If you did not request this code, please contact your site administrator immediately.

Regards,
%s', 'cadssl'),
                        $user->display_name,
                        get_bloginfo('name'),
                        $code,
                        $this->options['code_expiration'],
                        get_bloginfo('name')
                    );
                }
                
                return wp_mail($user->user_email, $subject, $message);
            
            default:
                return false;
        }
    }
    
    /**
     * Get user's preferred 2FA method
     * 
     * @param int $user_id User ID
     * @return string Method name
     */
    private function get_user_preferred_method($user_id) {
        $method = get_user_meta($user_id, 'cadssl_2fa_method', true);
        
        if (!$method || !in_array($method, $this->options['available_methods'])) {
            $method = $this->options['default_method'];
        }
        
        return $method;
    }
    
    /**
     * Get method label
     * 
     * @param string $method Method name
     * @return string Method label
     */
    private function get_method_label($method) {
        switch ($method) {
            case 'email':
                return __('email address', 'cadssl');
            default:
                return $method;
        }
    }
    
    /**
     * Check if remember device is enabled
     * 
     * @return bool Whether remember device is enabled
     */
    private function is_remember_device_enabled() {
        return isset($this->options['remember_device']) && $this->options['remember_device'];
    }
    
    /**
     * Set remember device cookie
     * 
     * @param string $username Username
     * @param WP_User $user User object
     */
    public function set_remember_cookie($username_or_user, $user = null) {
        // Allow passing either username or user object
        if (is_object($username_or_user)) {
            $user = $username_or_user;
        } elseif (is_null($user)) {
            $user = get_user_by('login', $username_or_user);
        }
        
        if (!$user || !$this->is_remember_device_enabled()) {
            return;
        }
        
        // Only set cookie if user has 2FA enabled
        if (!$this->user_requires_2fa($user)) {
            return;
        }
        
        // Generate random token
        $token = wp_generate_password(64, false);
        $hashed_token = wp_hash_password($token);
        
        // Store token hash in user meta
        $tokens = get_user_meta($user->ID, 'cadssl_remember_device_tokens', true);
        if (!is_array($tokens)) {
            $tokens = array();
        }
        
        // Add new token with expiration
        $expiration = time() + ($this->options['remember_duration'] * DAY_IN_SECONDS);
        $tokens[] = array(
            'token' => $hashed_token,
            'expires' => $expiration
        );
        
        // Clean up expired tokens
        $tokens = array_filter($tokens, function($token) {
            return isset($token['expires']) && $token['expires'] > time();
        });
        
        update_user_meta($user->ID, 'cadssl_remember_device_tokens', $tokens);
        
        // Set cookie
        $cookie_value = $user->ID . '|' . $token;
        $cookie_expiration = time() + ($this->options['remember_duration'] * DAY_IN_SECONDS);
        setcookie('cadssl_remember_device', $cookie_value, $cookie_expiration, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
    }
    
    /**
     * Verify remember device cookie
     * 
     * @param int $user_id User ID
     * @return bool Whether cookie is valid
     */
    private function verify_remember_cookie($user_id) {
        // Check if cookie exists
        if (!isset($_COOKIE['cadssl_remember_device'])) {
            return false;
        }
        
        // Parse cookie value
        $cookie_parts = explode('|', $_COOKIE['cadssl_remember_device']);
        if (count($cookie_parts) !== 2) {
            return false;
        }
        
        list($cookie_user_id, $token) = $cookie_parts;
        
        // Check if user IDs match
        if (intval($cookie_user_id) !== $user_id) {
            return false;
        }
        
        // Get stored tokens
        $tokens = get_user_meta($user_id, 'cadssl_remember_device_tokens', true);
        if (!is_array($tokens)) {
            return false;
        }
        
        // Check each token
        foreach ($tokens as $key => $stored) {
            if (!isset($stored['token']) || !isset($stored['expires'])) {
                continue;
            }
            
            // Check if token is expired
            if ($stored['expires'] < time()) {
                continue;
            }
            
            // Verify token
            if (wp_check_password($token, $stored['token'])) {
                return true;
            }
        }
        
        return false;
    }
}