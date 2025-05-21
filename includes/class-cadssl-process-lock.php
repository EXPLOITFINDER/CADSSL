<?php
/**
 * Process Lock Manager
 * 
 * Manages process locks to prevent concurrent execution of resource-intensive operations
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class CADSSL_Process_Lock {
    /**
     * Lock name
     * @var string
     */
    private $lock_name;
    
    /**
     * Lock timeout in seconds
     * @var int
     */
    private $timeout;
    
    /**
     * Constructor
     * 
     * @param string $lock_name The name of the lock
     * @param int $timeout Lock timeout in seconds (default: 1 hour)
     */
    public function __construct($lock_name, $timeout = 3600) {
        $this->lock_name = sanitize_title($lock_name);
        $this->timeout = absint($timeout);
    }
    
    /**
     * Acquire a lock
     * 
     * @return bool True if lock was acquired, false if already locked
     */
    public function acquire() {
        $lock_key = 'cadssl_lock_' . $this->lock_name;
        
        // Check if lock exists and is still valid
        $existing_lock = get_option($lock_key);
        
        if ($existing_lock) {
            // If lock has expired, we can override it
            if (time() - $existing_lock['time'] > $this->timeout) {
                $this->release();
            } else {
                // Lock is still valid
                return false;
            }
        }
        
        // Create new lock
        $lock_data = array(
            'time' => time(),
            'user_id' => get_current_user_id(),
            'process_id' => getmypid() ?: rand(1000, 9999)
        );
        
        return update_option($lock_key, $lock_data, false);
    }
    
    /**
     * Release a lock
     * 
     * @return bool True if lock was released, false otherwise
     */
    public function release() {
        $lock_key = 'cadssl_lock_' . $this->lock_name;
        return delete_option($lock_key);
    }
    
    /**
     * Check if a lock exists
     * 
     * @return bool True if locked, false otherwise
     */
    public function is_locked() {
        $lock_key = 'cadssl_lock_' . $this->lock_name;
        $lock = get_option($lock_key);
        
        if (!$lock) {
            return false;
        }
        
        // Check if lock has expired
        if (time() - $lock['time'] > $this->timeout) {
            $this->release();
            return false;
        }
        
        return true;
    }
    
    /**
     * Get lock information
     * 
     * @return array|false Lock data or false if not locked
     */
    public function get_lock_info() {
        $lock_key = 'cadssl_lock_' . $this->lock_name;
        $lock = get_option($lock_key);
        
        if (!$lock) {
            return false;
        }
        
        return $lock;
    }
    
    /**
     * Static method to clean up expired locks
     */
    public static function cleanup_expired_locks() {
        global $wpdb;
        
        $lock_keys = $wpdb->get_results(
            "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE 'cadssl_lock_%'"
        );
        
        foreach ($lock_keys as $lock) {
            $lock_data = maybe_unserialize($lock->option_value);
            
            // If lock is older than 2 hours, remove it
            if (isset($lock_data['time']) && time() - $lock_data['time'] > 7200) {
                delete_option($lock->option_name);
            }
        }
    }
}
