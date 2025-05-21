<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class CADSSL_API {
    /**
     * API Version
     */
    const VERSION = '1.0';
    
    /**
     * Initialize API
     */
    public function init() {
        add_action('rest_api_init', array($this, 'register_rest_routes'));
    }
    
    /**
     * Register REST API routes
     */
    public function register_rest_routes() {
        register_rest_route('cadssl/v1', '/status', array(
            'methods' => 'GET',
            'callback' => array($this, 'get_security_status'),
            'permission_callback' => array($this, 'check_api_permissions')
        ));
        
        register_rest_route('cadssl/v1', '/scan', array(
            'methods' => 'POST',
            'callback' => array($this, 'start_security_scan'),
            'permission_callback' => array($this, 'check_api_permissions')
        ));

        // Registrare altri endpoint REST
        // ...existing code...
    }

    /**
     * Check API permissions
     */
    public function check_api_permissions() {
        return current_user_can('manage_options');
    }

    /**
     * Get security status
     */
    public function get_security_status($request) {
        // Implementazione dettagliata
        // ...existing code...
    }

    // Implementare altri metodi API
    // ...existing code...
}
