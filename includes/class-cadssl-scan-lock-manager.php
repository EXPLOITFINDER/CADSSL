<?php
/**
 * Scan Lock Manager
 * 
 * Handles creating, checking, and clearing scan locks to prevent multiple scans
 * from running simultaneously and to handle stale locks.
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class CADSSL_Scan_Lock_Manager {

    /**
     * The lock option name in the database
     */
    const LOCK_OPTION = 'cadssl_scan_lock';
    
    /**
     * Max age of lock in seconds (20 minutes)
     */
    const MAX_LOCK_AGE = 1200;
    
    /**
     * Create a new scan lock
     *
     * @param string $scan_type The type of scan being performed
     * @return bool True if lock was created, false if a lock already exists
     */
    public static function create_lock($scan_type = 'malware_scan') {
        // Check if lock already exists
        $existing_lock = self::get_lock();
        
        if ($existing_lock) {
            // Check if the lock is stale
            if (self::is_lock_stale($existing_lock)) {
                self::force_clear_lock($existing_lock);
            } else {
                return false; // Valid lock exists
            }
        }
        
        // Create new lock
        $lock_data = array(
            'created' => time(),
            'user_id' => get_current_user_id(),
            'process_id' => 'process_' . uniqid(),
            'scan_type' => $scan_type,
            'status' => 'running'
        );
        
        return update_option(self::LOCK_OPTION, $lock_data);
    }
    
    /**
     * Check if a scan lock exists
     *
     * @return bool True if a valid lock exists, false otherwise
     */
    public static function lock_exists() {
        $lock = self::get_lock();
        
        if (!$lock) {
            return false;
        }
        
        // Check if the lock is stale
        if (self::is_lock_stale($lock)) {
            self::force_clear_lock($lock);
            return false;
        }
        
        return true;
    }
    
    /**
     * Get the current lock data
     *
     * @return array|false Lock data array or false if no lock exists
     */
    public static function get_lock() {
        return get_option(self::LOCK_OPTION, false);
    }
    
    /**
     * Release the current lock
     *
     * @param string $process_id The process ID of the lock to release
     * @return bool True if lock was released, false otherwise
     */
    public static function release_lock($process_id = null) {
        $lock = self::get_lock();
        
        // No lock to release
        if (!$lock) {
            return true;
        }
        
        // If process ID is provided, only release if it matches
        if ($process_id && $lock['process_id'] !== $process_id) {
            return false;
        }
        
        return delete_option(self::LOCK_OPTION);
    }
    
    /**
     * Update lock status
     *
     * @param string $status New status of the lock
     * @param string $process_id The process ID to update
     * @return bool True if the lock was updated, false otherwise
     */
    public static function update_lock_status($status, $process_id = null) {
        $lock = self::get_lock();
        
        if (!$lock) {
            return false;
        }
        
        // If process ID is provided, only update if it matches
        if ($process_id && $lock['process_id'] !== $process_id) {
            return false;
        }
        
        $lock['status'] = $status;
        $lock['last_updated'] = time();
        
        return update_option(self::LOCK_OPTION, $lock);
    }
    
    /**
     * Check if a lock is stale (older than the max age)
     *
     * @param array $lock Lock data
     * @return bool True if the lock is stale
     */
    public static function is_lock_stale($lock) {
        $lock_age = time() - $lock['created'];
        return $lock_age > self::MAX_LOCK_AGE;
    }
    
    /**
     * Force clear a lock if needed
     *
     * @param array $lock Lock data
     * @return bool True if the lock was cleared
     */
    public static function force_clear_lock($lock = null) {
        if (is_null($lock)) {
            $lock = self::get_lock();
        }
        
        if (!$lock) {
            return true;
        }
        
        // Log the forced clearing of a lock
        error_log(sprintf(
            'CADSSL Security: Force clearing stale scan lock. Created: %s, User: %d, Process: %s',
            date('Y-m-d H:i:s', $lock['created']),
            $lock['user_id'],
            $lock['process_id']
        ));
        
        return delete_option(self::LOCK_OPTION);
    }
    
    /**
     * Get human-readable lock information
     *
     * @return string HTML formatted lock information
     */
    public static function get_lock_info_html() {
        $lock = self::get_lock();
        
        if (!$lock) {
            return '';
        }
        
        $lock_age_seconds = time() - $lock['created'];
        
        if ($lock_age_seconds < 60) {
            $lock_age = $lock_age_seconds . ' ' . __('seconds ago', 'cadssl');
        } elseif ($lock_age_seconds < 3600) {
            $lock_age = floor($lock_age_seconds / 60) . ' ' . __('minutes ago', 'cadssl');
        } else {
            $lock_age = floor($lock_age_seconds / 3600) . ' ' . __('hours ago', 'cadssl');
        }
        
        $html = '<div class="cadssl-lock-info">';
        $html .= '<h3>' . __('Scan Lock Detected', 'cadssl') . '</h3>';
        $html .= '<p>' . __('A scan lock is currently active which is preventing new scans. This could mean:', 'cadssl') . '</p>';
        $html .= '<ul>';
        $html .= '<li>' . __('A scan is currently running through WP-Cron in the background', 'cadssl') . '</li>';
        $html .= '<li>' . __('A previous scan did not complete properly and did not release the lock', 'cadssl') . '</li>';
        $html .= '</ul>';
        
        $html .= '<h4>' . __('Lock Information:', 'cadssl') . '</h4>';
        $html .= '<ul>';
        $html .= '<li><strong>' . __('Created:', 'cadssl') . '</strong> ' . date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $lock['created']) . ' (' . $lock_age . ')</li>';
        $html .= '<li><strong>' . __('User ID:', 'cadssl') . '</strong> ' . $lock['user_id'] . '</li>';
        $html .= '<li><strong>' . __('Process ID:', 'cadssl') . '</strong> ' . $lock['process_id'] . '</li>';
        
        if (isset($lock['status'])) {
            $html .= '<li><strong>' . __('Status:', 'cadssl') . '</strong> ' . $lock['status'] . '</li>';
        }
        
        $html .= '</ul>';
        
        if (self::is_lock_stale($lock)) {
            $html .= '<p><a href="#" class="button button-primary cadssl-clear-lock" data-nonce="' . wp_create_nonce('cadssl_clear_lock') . '">' . __('Clear Stale Lock', 'cadssl') . '</a></p>';
        }
        
        $html .= '</div>';
        
        return $html;
    }
}
