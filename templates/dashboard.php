<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="wrap">
    <h1><?php echo esc_html__('CADSSL Security Dashboard', 'cadssl'); ?></h1>
    
    <div class="cadssl-dashboard-container">
        <div class="cadssl-card">
            <h2><?php echo esc_html__('SSL Status', 'cadssl'); ?></h2>
            <div class="cadssl-card-content">
                <?php 
                $is_ssl = is_ssl();
                if ($is_ssl) {
                    echo '<p class="status-secure">' . esc_html__('Your site is using SSL/HTTPS', 'cadssl') . '</p>';
                } else {
                    echo '<p class="status-insecure">' . esc_html__('Your site is not using SSL/HTTPS', 'cadssl') . '</p>';
                }
                ?>
            </div>
        </div>
        
        <div class="cadssl-card">
            <h2><?php echo esc_html__('Security Overview', 'cadssl'); ?></h2>
            <div class="cadssl-card-content">
                <p><?php echo esc_html__('Welcome to CADSSL Security. Use the menu options to configure security features.', 'cadssl'); ?></p>
                <a href="<?php echo esc_url(admin_url('admin.php?page=cadssl-settings')); ?>" class="button button-primary"><?php echo esc_html__('Configure Settings', 'cadssl'); ?></a>
            </div>
        </div>
    </div>
</div>
