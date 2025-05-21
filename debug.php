<?php
/**
 * Debug helper for CADSSL Security
 * 
 * Place this file in your WordPress root directory and access it directly via browser
 * to diagnose plugin issues. Remember to remove this file when finished debugging.
 */

// Basic WordPress initialization
define('WP_USE_THEMES', false);
require_once('./wp-load.php');

// Only allow access to administrators
if (!current_user_can('manage_options')) {
    wp_die('You do not have sufficient permissions to access this page.');
}

echo '<h1>CADSSL Security Debug Tool</h1>';

// Check required directories
echo '<h2>Directory Structure Check</h2>';
$plugin_dir = WP_PLUGIN_DIR . '/cadssl-security';
$required_dirs = array(
    $plugin_dir,
    $plugin_dir . '/includes',
    $plugin_dir . '/assets',
    $plugin_dir . '/assets/css',
    $plugin_dir . '/assets/js',
);

foreach ($required_dirs as $dir) {
    echo 'Directory: ' . $dir . ' - ';
    if (is_dir($dir)) {
        echo '<span style="color:green">EXISTS</span>';
    } else {
        echo '<span style="color:red">MISSING</span>';
    }
    echo '<br>';
}

// Check required files
echo '<h2>Required Files Check</h2>';
$required_files = array(
    $plugin_dir . '/ssl.php',
    $plugin_dir . '/includes/class-cadssl-core.php',
    $plugin_dir . '/includes/class-cadssl-ssl-checker.php',
    $plugin_dir . '/includes/class-cadssl-security-headers.php',
    $plugin_dir . '/includes/class-cadssl-admin.php',
);

foreach ($required_files as $file) {
    echo 'File: ' . $file . ' - ';
    if (file_exists($file)) {
        echo '<span style="color:green">EXISTS</span>';
    } else {
        echo '<span style="color:red">MISSING</span>';
    }
    echo '<br>';
}

// Check PHP version
echo '<h2>PHP Environment</h2>';
echo 'PHP Version: ' . phpversion() . '<br>';
echo 'Memory Limit: ' . ini_get('memory_limit') . '<br>';
echo 'Max Execution Time: ' . ini_get('max_execution_time') . '<br>';

// Check required PHP extensions
$required_extensions = array('openssl', 'curl', 'mbstring', 'json');
echo '<h3>PHP Extensions</h3>';
foreach ($required_extensions as $ext) {
    echo $ext . ': ';
    echo extension_loaded($ext) ? '<span style="color:green">LOADED</span>' : '<span style="color:red">MISSING</span>';
    echo '<br>';
}

// Get active plugins
echo '<h2>Active Plugins</h2>';
$active_plugins = get_option('active_plugins');
echo '<ul>';
foreach ($active_plugins as $plugin) {
    echo '<li>' . $plugin . '</li>';
}
echo '</ul>';

// Check WordPress version
echo '<h2>WordPress Environment</h2>';
echo 'WordPress Version: ' . get_bloginfo('version') . '<br>';
echo 'Site URL: ' . get_site_url() . '<br>';
echo 'Home URL: ' . get_home_url() . '<br>';
echo 'SSL Used: ' . (is_ssl() ? 'Yes' : 'No') . '<br>';

// Check error logs
echo '<h2>Latest Error Log Entries</h2>';
$error_log_path = ini_get('error_log');
if (file_exists($error_log_path) && is_readable($error_log_path)) {
    $error_log = file_get_contents($error_log_path);
    $error_lines = array_filter(explode("\n", $error_log), function($line) {
        return stripos($line, 'cadssl') !== false;
    });
    $error_lines = array_slice($error_lines, -10);
    
    if (empty($error_lines)) {
        echo 'No CADSSL-related errors found in log.';
    } else {
        echo '<pre>' . implode("\n", $error_lines) . '</pre>';
    }
} else {
    echo 'Error log not accessible.';
}

echo '<h2>Next Steps</h2>';
echo '<p>Based on the information above, here are possible solutions:</p>';
echo '<ol>';
echo '<li>Ensure all required files are in the correct locations</li>';
echo '<li>Check for PHP syntax errors in your plugin files</li>';
echo '<li>Try disabling other plugins to check for conflicts</li>';
echo '<li>Make sure your server meets the minimum requirements</li>';
echo '<li>Review the error logs for specific error messages</li>';
echo '</ol>';
