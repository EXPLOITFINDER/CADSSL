<?php
/**
 * Scanner Helper Class
 * 
 * Provides utility functions for the malware scanner to handle different
 * hosting environments and limitations.
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class CADSSL_Scanner_Helper {

    /**
     * Maximum filesize to scan (in bytes) - 5MB default
     */
    const MAX_FILESIZE = 5242880;
    
    /**
     * Maximum files to process in one batch
     */
    const MAX_FILES_PER_BATCH = 100;
    
    /**
     * Maximum execution time in seconds to allow for safe operation
     */
    const EXECUTION_TIME_LIMIT = 25;
    
    /**
     * Get the available memory limit in bytes
     * 
     * @return int Available memory in bytes
     */
    public static function get_memory_limit() {
        $memory_limit = ini_get('memory_limit');
        
        // Convert to bytes if not in bytes
        if (preg_match('/^(\d+)(.)$/', $memory_limit, $matches)) {
            if ($matches[2] == 'M') {
                $memory_limit = $matches[1] * 1024 * 1024;
            } else if ($matches[2] == 'K') {
                $memory_limit = $matches[1] * 1024;
            } else if ($matches[2] == 'G') {
                $memory_limit = $matches[1] * 1024 * 1024 * 1024;
            }
        }
        
        // Leave 20% of memory for other operations
        return $memory_limit * 0.8;
    }
    
    /**
     * Get the maximum execution time for the scan
     * 
     * @return int Maximum execution time in seconds
     */
    public static function get_max_execution_time() {
        $max_execution = ini_get('max_execution_time');
        
        // If unlimited or very high, cap it for safety
        if ($max_execution == 0 || $max_execution > 60) {
            $max_execution = self::EXECUTION_TIME_LIMIT;
        } else {
            // Leave 5 seconds margin
            $max_execution = max(5, $max_execution - 5);
        }
        
        return $max_execution;
    }
    
    /**
     * Calculate optimal batch size based on server resources
     * 
     * @return int Optimal number of files per batch
     */
    public static function calculate_optimal_batch_size() {
        $available_memory = self::get_memory_limit();
        $max_execution_time = self::get_max_execution_time();
        
        // Estimate memory usage per file (conservative estimate: 500KB)
        $memory_per_file = 512 * 1024;
        
        // Estimate time per file (conservative estimate: 0.2 seconds)
        $time_per_file = 0.2;
        
        // Calculate batch sizes based on constraints
        $memory_batch_size = floor($available_memory / $memory_per_file);
        $time_batch_size = floor($max_execution_time / $time_per_file);
        
        // Use the most restrictive constraint
        $optimal_batch_size = min($memory_batch_size, $time_batch_size, self::MAX_FILES_PER_BATCH);
        
        // Always return at least 10 files per batch, but never more than MAX_FILES_PER_BATCH
        return max(10, min($optimal_batch_size, self::MAX_FILES_PER_BATCH));
    }
    
    /**
     * Check if we're running out of resources
     * 
     * @param float $start_time The time when the scan started
     * @return bool True if we're running out of resources
     */
    public static function is_reaching_limits($start_time) {
        // Check execution time
        $elapsed = microtime(true) - $start_time;
        $max_execution = self::get_max_execution_time();
        
        if ($elapsed >= ($max_execution * 0.8)) {
            return true;
        }
        
        // Check memory usage
        $memory_usage = memory_get_usage();
        $memory_limit = self::get_memory_limit();
        
        if ($memory_usage >= ($memory_limit * 0.8)) {
            return true;
        }
        
        return false;
    }
}
