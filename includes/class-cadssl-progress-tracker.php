<?php
/**
 * Progress Tracker Class
 * 
 * Provides consistent tracking of background scan progress across multiple requests 
 * and browser sessions, fixing issues with inconsistent progress display.
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class CADSSL_Progress_Tracker {
    
    /**
     * Get the progress storage path
     * 
     * @param string $scan_id The scan ID
     * @return string Path to the progress file
     */
    private static function get_progress_path($scan_id) {
        // Ensure we have a valid scan ID
        if (empty($scan_id) || !preg_match('/^scan_[a-z0-9]+$/', $scan_id)) {
            return false;
        }
        
        // Create the logs directory if it doesn't exist
        $log_dir = CADSSL_PATH . 'logs';
        if (!file_exists($log_dir)) {
            wp_mkdir_p($log_dir);
        }
        
        return $log_dir . '/progress_' . $scan_id . '.json';
    }
    
    /**
     * Update scan progress
     * 
     * @param string $scan_id The scan ID
     * @param array $progress_data Progress data to save
     * @return bool Success or failure
     */
    public static function update_progress($scan_id, $progress_data) {
        $file_path = self::get_progress_path($scan_id);
        if (!$file_path) {
            return false;
        }
        
        // Ensure we have the minimum required data
        $required_keys = ['scanned_files', 'total_files', 'status', 'last_active'];
        foreach ($required_keys as $key) {
            if (!isset($progress_data[$key])) {
                return false;
            }
        }
        
        // Add timestamp of this update
        $progress_data['update_time'] = time();
        
        // Calculate progress percentage
        if ($progress_data['total_files'] > 0) {
            $progress_data['progress_percent'] = min(100, round(($progress_data['scanned_files'] / $progress_data['total_files']) * 100, 1));
        } else {
            $progress_data['progress_percent'] = 0;
        }
        
        // Write to file
        return (file_put_contents($file_path, json_encode($progress_data)) !== false);
    }
    
    /**
     * Get scan progress
     * 
     * @param string $scan_id The scan ID
     * @return array|bool Progress data or false if not found
     */
    public static function get_progress($scan_id) {
        $file_path = self::get_progress_path($scan_id);
        if (!$file_path || !file_exists($file_path)) {
            return false;
        }
        
        $data = json_decode(file_get_contents($file_path), true);
        if (!$data) {
            return false;
        }
        
        // Check if scan is active (last update within 60 seconds)
        $data['is_active'] = (time() - $data['update_time'] < 60);
        
        return $data;
    }
    
    /**
     * Delete scan progress
     * 
     * @param string $scan_id The scan ID
     * @return bool Success or failure
     */
    public static function delete_progress($scan_id) {
        $file_path = self::get_progress_path($scan_id);
        if (!$file_path || !file_exists($file_path)) {
            return false;
        }
        
        return @unlink($file_path);
    }
    
    /**
     * Clean up old progress files
     * 
     * @param int $max_age Maximum age in seconds
     * @return int Number of files deleted
     */
    public static function clean_old_progress_files($max_age = 86400) {
        $log_dir = CADSSL_PATH . 'logs';
        if (!file_exists($log_dir)) {
            return 0;
        }
        
        $deleted = 0;
        $files = glob($log_dir . '/progress_*.json');
        $now = time();
        
        foreach ($files as $file) {
            if ($now - filemtime($file) > $max_age) {
                if (@unlink($file)) {
                    $deleted++;
                }
            }
        }
        
        return $deleted;
    }
}
