<?php
/**
 * CADSSL Error Recovery Tool
 * 
 * This tool helps fix common issues with the CADSSL Security plugin
 * Run this file directly from the browser after copying it to your WordPress root
 */

// Basic WordPress initialization
define('WP_USE_THEMES', false);
require_once('./wp-load.php');

// Security check - only allow administrators
if (!current_user_can('manage_options')) {
    wp_die('You do not have sufficient permissions to access this page.');
}

// Header
echo '<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CADSSL Error Recovery Tool</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        button { padding: 10px; margin: 5px; cursor: pointer; }
        .action-box { background: #f5f5f5; padding: 15px; margin: 15px 0; border: 1px solid #ddd; }
    </style>
</head>
<body>
    <h1>CADSSL Error Recovery Tool</h1>
    <p>This tool helps resolve common issues that might be causing the critical error.</p>';

// Functions for fixing issues
function deactivate_plugin() {
    if (!function_exists('deactivate_plugins')) {
        require_once(ABSPATH . 'wp-admin/includes/plugin.php');
    }
    
    $plugin_file = 'cadssl-security/ssl.php';
    if (is_plugin_active($plugin_file)) {
        deactivate_plugins($plugin_file);
        return true;
    }
    return false;
}

function reset_plugin_options() {
    delete_option('cadssl_options');
    delete_option('cadssl_advanced_headers_options');
    delete_option('cadssl_gdpr_options');
    delete_option('cadssl_last_scan_results');
    delete_option('cadssl_last_scan_time');
    delete_option('cadssl_last_permissions_scan');
    delete_option('cadssl_last_permissions_scan_time');
    delete_option('cadssl_last_malware_scan');
    delete_option('cadssl_last_malware_scan_time');
    delete_option('cadssl_certificate_expiration');
    delete_option('cadssl_ssl_detected');
    
    return true;
}

function check_table_rows() {
    global $wpdb;
    $issue_found = false;
    
    // List of tables to check
    $tables = array($wpdb->options);
    
    foreach ($tables as $table) {
        // Check if table exists
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '{$table}'");
        if (!$table_exists) {
            echo "<p class='error'>Table {$table} does not exist!</p>";
            $issue_found = true;
            continue;
        }
        
        // Check for corrupted rows in options table
        if ($table === $wpdb->options) {
            $corrupted_options = $wpdb->get_results("SELECT * FROM {$wpdb->options} WHERE option_name LIKE '%cadssl%' AND option_value LIKE '%���%'");
            if ($corrupted_options) {
                echo "<p class='warning'>Found potentially corrupted CADSSL options in the database.</p>";
                foreach ($corrupted_options as $option) {
                    echo "<p>Corrupted option: {$option->option_name}</p>";
                    $wpdb->delete($wpdb->options, array('option_id' => $option->option_id));
                }
                echo "<p class='success'>Removed corrupted options.</p>";
                $issue_found = true;
            }
        }
    }
    
    if (!$issue_found) {
        echo "<p class='success'>No database issues detected.</p>";
    }
    
    return $issue_found;
}

// Handle form submissions
if (isset($_POST['action'])) {
    $action = $_POST['action'];
    
    switch ($action) {
        case 'deactivate':
            if (deactivate_plugin()) {
                echo "<p class='success'>Plugin deactivated successfully. You can now re-activate it from the plugins page.</p>";
            } else {
                echo "<p class='error'>Could not deactivate the plugin or it's already inactive.</p>";
            }
            break;
            
        case 'reset_options':
            if (reset_plugin_options()) {
                echo "<p class='success'>Plugin options have been reset. The plugin will use default settings when activated next.</p>";
            } else {
                echo "<p class='error'>Could not reset plugin options.</p>";
            }
            break;
            
        case 'check_db':
            check_table_rows();
            break;
    }
}

// Show action buttons
echo '
<div class="action-box">
    <h2>Available Actions</h2>
    
    <form method="post">
        <h3>1. Deactivate Plugin</h3>
        <p>This will safely deactivate the plugin to stop the critical error.</p>
        <button type="submit" name="action" value="deactivate">Deactivate Plugin</button>
    
        <h3>2. Reset Plugin Options</h3>
        <p>This will delete all plugin settings and restore defaults.</p>
        <button type="submit" name="action" value="reset_options">Reset Plugin Options</button>
    
        <h3>3. Check Database</h3>
        <p>This will check for and fix database issues related to the plugin.</p>
        <button type="submit" name="action" value="check_db">Check Database</button>
    </form>
</div>

<div class="action-box">
    <h2>Next Steps</h2>
    <p>After resolving the issues:</p>
    <ol>
        <li>Try activating the plugin again from the Plugins page</li>
        <li>If you continue to experience issues, try the minimal version of the plugin</li>
        <li>Check your server\'s error logs for more specific information</li>
    </ol>
</div>';

// Footer
echo '</body></html>';
