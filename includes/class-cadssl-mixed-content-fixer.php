<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class CADSSL_Mixed_Content_Fixer {
    /**
     * Initialize mixed content fixer
     */
    public function init() {
        // Only run if SSL is active
        if (is_ssl()) {
            // Filter content to fix mixed content
            add_filter('the_content', array($this, 'fix_content'), 999);
            add_filter('widget_text', array($this, 'fix_content'), 999);
            
            // Fix scripts and styles
            add_filter('script_loader_src', array($this, 'fix_url'));
            add_filter('style_loader_src', array($this, 'fix_url'));
            
            // Fix URLs in custom fields
            add_filter('wp_get_attachment_url', array($this, 'fix_url'), 10);
            add_filter('wp_get_attachment_image_src', array($this, 'fix_image_src'), 10);
            
            // Fix URLs in theme
            add_filter('theme_root_uri', array($this, 'fix_url'), 10);
            add_filter('plugins_url', array($this, 'fix_url'), 10);
            add_filter('includes_url', array($this, 'fix_url'), 10);
            add_filter('content_url', array($this, 'fix_url'), 10);
        }
    }
    
    /**
     * Fix URLs in content
     * 
     * @param string $content The content to fix
     * @return string Fixed content
     */
    public function fix_content($content) {
        // Don't fix if not SSL
        if (!is_ssl()) {
            return $content;
        }
        
        // Replace http: URLs with https: (except for links to external domains)
        $domain = parse_url(home_url(), PHP_URL_HOST);
        $pattern = '/(http:\/\/' . preg_quote($domain, '/') . '[^\s")\']+)/i';
        $content = preg_replace_callback($pattern, array($this, 'replace_url'), $content);
        
        return $content;
    }
    
    /**
     * Fix a single URL
     * 
     * @param string $url The URL to fix
     * @return string Fixed URL
     */
    public function fix_url($url) {
        if (!is_ssl() || !is_string($url) || empty($url)) {
            return $url;
        }
        
        // Only replace http with https for internal URLs
        if (strpos($url, 'http://') === 0) {
            $domain = parse_url(home_url(), PHP_URL_HOST);
            if (strpos($url, 'http://' . $domain) === 0) {
                $url = str_replace('http://', 'https://', $url);
            }
        }
        
        return $url;
    }
    
    /**
     * Fix image source
     * 
     * @param array $image Image data array
     * @return array Fixed image data
     */
    public function fix_image_src($image) {
        if (!is_ssl() || !is_array($image)) {
            return $image;
        }
        
        if (isset($image[0])) {
            $image[0] = $this->fix_url($image[0]);
        }
        
        return $image;
    }
    
    /**
     * URL replacement callback
     * 
     * @param array $matches Regex matches
     * @return string Fixed URL
     */
    public function replace_url($matches) {
        return str_replace('http://', 'https://', $matches[0]);
    }
    
    /**
     * Add mixed content submenu
     */
    public function add_mixed_content_menu() {
        // Make sure the parent menu exists before adding submenu
        global $submenu;
        if (!isset($submenu['cadssl-settings'])) {
            return;
        }
        
        add_submenu_page(
            'cadssl-settings',
            __('Mixed Content', 'cadssl'),
            __('Mixed Content', 'cadssl'),
            'manage_options',
            'cadssl-mixed-content',
            array($this, 'display_mixed_content_page')
        );
    }
    
    /**
     * Start output buffer for fixing inline scripts/styles
     */
    public function start_buffer() {
        ob_start(array($this, 'fix_content'));
    }
    
    /**
     * End output buffer
     */
    public function end_buffer() {
        if (ob_get_length()) {
            ob_end_flush();
        }
    }
    
    /**
     * Scan for mixed content in database
     * 
     * @param int $limit Maximum number of items to return
     * @return array Mixed content items found
     */
    public function scan_for_mixed_content($limit = 100) {
        global $wpdb;
        
        $results = array(
            'posts' => array(),
            'options' => array(),
            'metas' => array()
        );
        
        // Check posts
        $posts = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT ID, post_title, post_type, post_content FROM $wpdb->posts 
                WHERE post_status = 'publish' 
                AND post_content LIKE %s 
                LIMIT %d",
                '%http://%',
                $limit
            )
        );
        
        foreach ($posts as $post) {
            preg_match_all('~https?://([^"\'\s]+)~i', $post->post_content, $matches);
            $urls = array();
            
            foreach ($matches[0] as $url) {
                if (strpos($url, 'http://') === 0) {
                    $urls[] = $url;
                }
            }
            
            if (!empty($urls)) {
                $results['posts'][] = array(
                    'id' => $post->ID,
                    'title' => $post->post_title,
                    'type' => $post->post_type,
                    'edit_url' => get_edit_post_link($post->ID),
                    'urls' => array_unique($urls)
                );
            }
        }
        
        // Check options
        $options = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT option_name, option_value FROM $wpdb->options 
                WHERE option_value LIKE %s 
                LIMIT %d",
                '%http://%',
                $limit
            )
        );
        
        foreach ($options as $option) {
            if (in_array($option->option_name, array('home', 'siteurl'))) {
                continue; // Skip these as they're handled separately
            }
            
            preg_match_all('~https?://([^"\'\s]+)~i', $option->option_value, $matches);
            $urls = array();
            
            foreach ($matches[0] as $url) {
                if (strpos($url, 'http://') === 0) {
                    $urls[] = $url;
                }
            }
            
            if (!empty($urls)) {
                $results['options'][] = array(
                    'name' => $option->option_name,
                    'urls' => array_unique($urls)
                );
            }
        }
        
        // Check meta
        $metas = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT post_id, meta_key, meta_value FROM $wpdb->postmeta 
                WHERE meta_value LIKE %s 
                LIMIT %d",
                '%http://%',
                $limit
            )
        );
        
        foreach ($metas as $meta) {
            preg_match_all('~https?://([^"\'\s]+)~i', $meta->meta_value, $matches);
            $urls = array();
            
            foreach ($matches[0] as $url) {
                if (strpos($url, 'http://') === 0) {
                    $urls[] = $url;
                }
            }
            
            if (!empty($urls)) {
                $post_type = get_post_type($meta->post_id);
                $post_title = get_the_title($meta->post_id);
                
                $results['metas'][] = array(
                    'post_id' => $meta->post_id,
                    'post_title' => $post_title,
                    'post_type' => $post_type,
                    'meta_key' => $meta->meta_key,
                    'edit_url' => get_edit_post_link($meta->post_id),
                    'urls' => array_unique($urls)
                );
            }
        }
        
        return $results;
    }
    
    /**
     * Fix mixed content in database
     * 
     * @param array $items Items to fix (posts, options, metas)
     * @return array Results of fixing operation
     */
    public function fix_mixed_content($items) {
        global $wpdb;
        $results = array(
            'fixed' => 0,
            'failed' => 0,
            'details' => array()
        );
        
        // Fix posts
        if (!empty($items['posts'])) {
            foreach ($items['posts'] as $post_id) {
                $post = get_post($post_id);
                if (!$post) {
                    $results['failed']++;
                    continue;
                }
                
                $fixed_content = str_replace('http://', 'https://', $post->post_content);
                
                if ($fixed_content !== $post->post_content) {
                    $update = wp_update_post(array(
                        'ID' => $post_id,
                        'post_content' => $fixed_content
                    ));
                    
                    if ($update) {
                        $results['fixed']++;
                        $results['details'][] = sprintf(__('Fixed post: %s', 'cadssl'), $post->post_title);
                    } else {
                        $results['failed']++;
                    }
                }
            }
        }
        
        // Fix options
        if (!empty($items['options'])) {
            foreach ($items['options'] as $option_name) {
                $option_value = get_option($option_name);
                if (!$option_value) {
                    $results['failed']++;
                    continue;
                }
                
                if (is_string($option_value)) {
                    $fixed_value = str_replace('http://', 'https://', $option_value);
                    
                    if ($fixed_value !== $option_value) {
                        $update = update_option($option_name, $fixed_value);
                        
                        if ($update) {
                            $results['fixed']++;
                            $results['details'][] = sprintf(__('Fixed option: %s', 'cadssl'), $option_name);
                        } else {
                            $results['failed']++;
                        }
                    }
                } else if (is_array($option_value)) {
                    $fixed_value = $this->fix_array_urls($option_value);
                    
                    if ($fixed_value !== $option_value) {
                        $update = update_option($option_name, $fixed_value);
                        
                        if ($update) {
                            $results['fixed']++;
                            $results['details'][] = sprintf(__('Fixed option: %s', 'cadssl'), $option_name);
                        } else {
                            $results['failed']++;
                        }
                    }
                }
            }
        }
        
        // Fix meta
        if (!empty($items['metas'])) {
            foreach ($items['metas'] as $meta) {
                if (!isset($meta['post_id']) || !isset($meta['meta_key'])) {
                    $results['failed']++;
                    continue;
                }
                
                $meta_value = get_post_meta($meta['post_id'], $meta['meta_key'], true);
                if (!$meta_value) {
                    $results['failed']++;
                    continue;
                }
                
                if (is_string($meta_value)) {
                    $fixed_value = str_replace('http://', 'https://', $meta_value);
                    
                    if ($fixed_value !== $meta_value) {
                        $update = update_post_meta($meta['post_id'], $meta['meta_key'], $fixed_value, $meta_value);
                        
                        if ($update) {
                            $results['fixed']++;
                            $results['details'][] = sprintf(__('Fixed meta: %s for %s', 'cadssl'), $meta['meta_key'], get_the_title($meta['post_id']));
                        } else {
                            $results['failed']++;
                        }
                    }
                } else if (is_array($meta_value)) {
                    $fixed_value = $this->fix_array_urls($meta_value);
                    
                    if ($fixed_value !== $meta_value) {
                        $update = update_post_meta($meta['post_id'], $meta['meta_key'], $fixed_value, $meta_value);
                        
                        if ($update) {
                            $results['fixed']++;
                            $results['details'][] = sprintf(__('Fixed meta: %s for %s', 'cadssl'), $meta['meta_key'], get_the_title($meta['post_id']));
                        } else {
                            $results['failed']++;
                        }
                    }
                }
            }
        }
        
        return $results;
    }
    
    /**
     * Fix URLs in an array recursively
     * 
     * @param array $array The array to process
     * @return array The processed array
     */
    private function fix_array_urls($array) {
        foreach ($array as $key => $value) {
            if (is_array($value)) {
                $array[$key] = $this->fix_array_urls($value);
            } elseif (is_string($value)) {
                $array[$key] = str_replace('http://', 'https://', $value);
            }
        }
        
        return $array;
    }
    
    /**
     * Display mixed content scanner and fixer page
     */
    public function display_mixed_content_page() {
        // Check if the form was submitted to fix mixed content
        $fixed_results = null;
        if (isset($_POST['cadssl_fix_mixed_content']) && isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], 'cadssl_fix_mixed_content')) {
            $items_to_fix = array(
                'posts' => isset($_POST['fix_posts']) ? $_POST['fix_posts'] : array(),
                'options' => isset($_POST['fix_options']) ? $_POST['fix_options'] : array(),
                'metas' => isset($_POST['fix_metas']) ? $_POST['fix_metas'] : array()
            );
            
            $fixed_results = $this->fix_mixed_content($items_to_fix);
        }
        
        // Get mixed content
        $mixed_content = $this->scan_for_mixed_content();
        $total_issues = count($mixed_content['posts']) + count($mixed_content['options']) + count($mixed_content['metas']);
        
        // Get options
        $options = get_option('cadssl_options', array());
        $auto_fix = isset($options['auto_fix_mixed_content']) ? $options['auto_fix_mixed_content'] : false;
        
        // Save auto-fix setting
        if (isset($_POST['save_auto_fix']) && isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], 'cadssl_save_auto_fix')) {
            $options['auto_fix_mixed_content'] = isset($_POST['auto_fix_mixed_content']);
            update_option('cadssl_options', $options);
            $auto_fix = $options['auto_fix_mixed_content'];
            
            // Set up or remove auto-fixing hooks based on new setting
            if ($auto_fix) {
                $this->setup_auto_fixing_hooks();
            } else {
                // No direct way to remove hooks, they'll be inactive until next page load
            }
            
            echo '<div class="notice notice-success"><p>' . __('Settings saved.', 'cadssl') . '</p></div>';
        }
        
        ?>
        <div class="wrap">
            <h1><?php _e('Mixed Content Scanner', 'cadssl'); ?></h1>
            
            <?php if ($fixed_results): ?>
            <div class="notice notice-success">
                <p>
                    <?php 
                    printf(
                        __('Fixed %d item(s). %d item(s) failed.', 'cadssl'),
                        $fixed_results['fixed'],
                        $fixed_results['failed']
                    ); 
                    ?>
                </p>
                <?php if (!empty($fixed_results['details'])): ?>
                <ul>
                    <?php foreach ($fixed_results['details'] as $detail): ?>
                    <li><?php echo esc_html($detail); ?></li>
                    <?php endforeach; ?>
                </ul>
                <?php endif; ?>
            </div>
            <?php endif; ?>
            
            <div class="card">
                <h2><?php _e('Auto-Fix Mixed Content', 'cadssl'); ?></h2>
                <form method="post" action="">
                    <?php wp_nonce_field('cadssl_save_auto_fix'); ?>
                    <p>
                        <input type="checkbox" id="auto_fix_mixed_content" name="auto_fix_mixed_content" value="1" <?php checked($auto_fix); ?>>
                        <label for="auto_fix_mixed_content">
                            <?php _e('Automatically fix mixed content on page load (recommended)', 'cadssl'); ?>
                        </label>
                    </p>
                    <p class="description">
                        <?php _e('This will replace http:// URLs with https:// on the fly when pages are loaded. It helps prevent mixed content warnings but may not fix all issues.', 'cadssl'); ?>
                    </p>
                    <p>
                        <input type="submit" name="save_auto_fix" class="button button-primary" value="<?php _e('Save Setting', 'cadssl'); ?>">
                    </p>
                </form>
            </div>
            
            <h2><?php _e('Mixed Content Scanner', 'cadssl'); ?></h2>
            
            <?php if ($total_issues === 0): ?>
                <div class="notice notice-success">
                    <p><?php _e('No mixed content issues found! Your site appears to be properly serving all content over HTTPS.', 'cadssl'); ?></p>
                </div>
            <?php else: ?>
                <div class="notice notice-warning">
                    <p>
                        <?php 
                        printf(
                            __('Found %d items with mixed content. You can fix them automatically using the form below.', 'cadssl'),
                            $total_issues
                        ); 
                        ?>
                    </p>
                </div>
                
                <form method="post" action="">
                    <?php wp_nonce_field('cadssl_fix_mixed_content'); ?>
                    
                    <?php if (!empty($mixed_content['posts'])): ?>
                    <h3><?php _e('Posts & Pages', 'cadssl'); ?></h3>
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th class="check-column"><input type="checkbox" id="select-all-posts"></th>
                                <th><?php _e('Title', 'cadssl'); ?></th>
                                <th><?php _e('Type', 'cadssl'); ?></th>
                                <th><?php _e('Mixed Content URLs', 'cadssl'); ?></th>
                                <th><?php _e('Actions', 'cadssl'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($mixed_content['posts'] as $post): ?>
                            <tr>
                                <td><input type="checkbox" name="fix_posts[]" value="<?php echo esc_attr($post['id']); ?>" class="post-checkbox"></td>
                                <td><?php echo esc_html($post['title']); ?></td>
                                <td><?php echo esc_html($post['type']); ?></td>
                                <td>
                                    <ul style="margin: 0; padding-left: 1em;">
                                        <?php foreach (array_slice($post['urls'], 0, 3) as $url): ?>
                                        <li><?php echo esc_html($url); ?></li>
                                        <?php endforeach; ?>
                                        <?php if (count($post['urls']) > 3): ?>
                                        <li>... <?php printf(__('and %d more', 'cadssl'), count($post['urls']) - 3); ?></li>
                                        <?php endif; ?>
                                    </ul>
                                </td>
                                <td>
                                    <a href="<?php echo esc_url($post['edit_url']); ?>" class="button button-small" target="_blank">
                                        <?php _e('Edit', 'cadssl'); ?>
                                    </a>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php endif; ?>
                    
                    <?php if (!empty($mixed_content['options'])): ?>
                    <h3><?php _e('Options', 'cadssl'); ?></h3>
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th class="check-column"><input type="checkbox" id="select-all-options"></th>
                                <th><?php _e('Option Name', 'cadssl'); ?></th>
                                <th><?php _e('Mixed Content URLs', 'cadssl'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($mixed_content['options'] as $option): ?>
                            <tr>
                                <td><input type="checkbox" name="fix_options[]" value="<?php echo esc_attr($option['name']); ?>" class="option-checkbox"></td>
                                <td><?php echo esc_html($option['name']); ?></td>
                                <td>
                                    <ul style="margin: 0; padding-left: 1em;">
                                        <?php foreach (array_slice($option['urls'], 0, 3) as $url): ?>
                                        <li><?php echo esc_html($url); ?></li>
                                        <?php endforeach; ?>
                                        <?php if (count($option['urls']) > 3): ?>
                                        <li>... <?php printf(__('and %d more', 'cadssl'), count($option['urls']) - 3); ?></li>
                                        <?php endif; ?>
                                    </ul>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php endif; ?>
                    
                    <?php if (!empty($mixed_content['metas'])): ?>
                    <h3><?php _e('Post Meta', 'cadssl'); ?></h3>
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th class="check-column"><input type="checkbox" id="select-all-metas"></th>
                                <th><?php _e('Post', 'cadssl'); ?></th>
                                <th><?php _e('Meta Key', 'cadssl'); ?></th>
                                <th><?php _e('Mixed Content URLs', 'cadssl'); ?></th>
                                <th><?php _e('Actions', 'cadssl'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($mixed_content['metas'] as $meta): ?>
                            <tr>
                                <td>
                                    <input type="checkbox" name="fix_metas[]" value="<?php 
                                        echo esc_attr(json_encode(array(
                                            'post_id' => $meta['post_id'],
                                            'meta_key' => $meta['meta_key']
                                        ))); 
                                    ?>" class="meta-checkbox">
                                </td>
                                <td><?php echo esc_html($meta['post_title']); ?> (<?php echo esc_html($meta['post_type']); ?>)</td>
                                <td><?php echo esc_html($meta['meta_key']); ?></td>
                                <td>
                                    <ul style="margin: 0; padding-left: 1em;">
                                        <?php foreach (array_slice($meta['urls'], 0, 3) as $url): ?>
                                        <li><?php echo esc_html($url); ?></li>
                                        <?php endforeach; ?>
                                        <?php if (count($meta['urls']) > 3): ?>
                                        <li>... <?php printf(__('and %d more', 'cadssl'), count($meta['urls']) - 3); ?></li>
                                        <?php endif; ?>
                                    </ul>
                                </td>
                                <td>
                                    <a href="<?php echo esc_url($meta['edit_url']); ?>" class="button button-small" target="_blank">
                                        <?php _e('Edit', 'cadssl'); ?>
                                    </a>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php endif; ?>
                    
                    <?php if ($total_issues > 0): ?>
                    <p>
                        <button type="button" class="button" id="select-all"><?php _e('Select All', 'cadssl'); ?></button>
                        <button type="button" class="button" id="deselect-all"><?php _e('Deselect All', 'cadssl'); ?></button>
                        <input type="submit" name="cadssl_fix_mixed_content" class="button button-primary" value="<?php _e('Fix Selected Items', 'cadssl'); ?>">
                    </p>
                    
                    <script>
                    jQuery(document).ready(function($) {
                        // Handle "Select All" button
                        $('#select-all').click(function() {
                            $('input[type="checkbox"]').prop('checked', true);
                        });
                        
                        // Handle "Deselect All" button
                        $('#deselect-all').click(function() {
                            $('input[type="checkbox"]').prop('checked', false);
                        });
                        
                        // Handle select all posts
                        $('#select-all-posts').change(function() {
                            $('.post-checkbox').prop('checked', $(this).prop('checked'));
                        });
                        
                        // Handle select all options
                        $('#select-all-options').change(function() {
                            $('.option-checkbox').prop('checked', $(this).prop('checked'));
                        });
                        
                        // Handle select all metas
                        $('#select-all-metas').change(function() {
                            $('.meta-checkbox').prop('checked', $(this).prop('checked'));
                        });
                    });
                    </script>
                    <?php endif; ?>
                </form>
            <?php endif; ?>
        </div>
        <?php
    }
}
