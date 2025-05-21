<?php
/**
 * CADSSL Security Uninstaller
 *
 * This file runs when the plugin is uninstalled.
 */

// If uninstall is not called from WordPress, exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Delete all plugin options
$options_to_delete = array(
    'cadssl_options',
    'cadssl_gdpr_options',
    'cadssl_advanced_headers_options',
    'cadssl_last_scan_results',
    'cadssl_last_scan_time',
    'cadssl_last_permissions_scan',
    'cadssl_last_permissions_scan_time',
    'cadssl_last_malware_scan',
    'cadssl_last_malware_scan_time',
    'cadssl_certificate_expiration',
    'cadssl_scan_lock',
    'cadssl_ssl_detected',
    'cadssl_scan_in_progress'
);

foreach ($options_to_delete as $option) {
    delete_option($option);
}

// Clear scheduled hooks
wp_clear_scheduled_hook('cadssl_daily_certificate_check');
wp_clear_scheduled_hook('cadssl_weekly_security_scan');
wp_clear_scheduled_hook('cadssl_weekly_permissions_scan');
wp_clear_scheduled_hook('cadssl_weekly_malware_scan');
wp_clear_scheduled_hook('cadssl_cleanup_locks');
wp_clear_scheduled_hook('cadssl_weekly_data_retention');

// Delete quarantine files if the directory exists
$quarantine_dir = plugin_dir_path(__FILE__) . 'quarantine';
if (is_dir($quarantine_dir)) {
    $files = glob($quarantine_dir . '/*');
    foreach ($files as $file) {
        if (is_file($file) && basename($file) !== '.htaccess' && basename($file) !== 'index.php') {
            @unlink($file);
        }
    }
}
