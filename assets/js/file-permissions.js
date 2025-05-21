/**
 * CADSSL Security - File Permissions JavaScript
 * Handles AJAX file permissions operations
 */
(function($) {
    'use strict';

    $(document).ready(function() {
        initFixPermissionsForm();
    });

    /**
     * Initialize fix permissions form
     */
    function initFixPermissionsForm() {
        $('#cadssl-fix-permissions-form').on('submit', function(e) {
            e.preventDefault();
            
            // Get selected files
            var selectedFiles = [];
            $('input[name="fix_files[]"]:checked').each(function() {
                selectedFiles.push($(this).val());
            });
            
            // Check if files are selected
            if (selectedFiles.length === 0) {
                showMessage('error', 'Please select at least one file to fix.');
                return;
            }
            
            // Show progress indicator
            $('.cadssl-save-indicator').show();
            $('#cadssl-fix-permissions-btn').prop('disabled', true);
            
            // Send AJAX request
            $.ajax({
                url: cadssl_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'cadssl_fix_permissions',
                    security: cadssl_ajax.nonce,
                    files: selectedFiles
                },
                success: function(response) {
                    // Hide progress indicator
                    $('.cadssl-save-indicator').hide();
                    $('#cadssl-fix-permissions-btn').prop('disabled', false);
                    
                    if (response.success) {
                        showMessage('success', response.data.message);
                        
                        // Reload page after short delay to show updated status
                        setTimeout(function() {
                            location.reload();
                        }, 1500);
                    } else {
                        showMessage('error', response.data.message || 'Failed to fix file permissions.');
                    }
                },
                error: function(xhr, status, error) {
                    // Hide progress indicator
                    $('.cadssl-save-indicator').hide();
                    $('#cadssl-fix-permissions-btn').prop('disabled', false);
                    
                    showMessage('error', 'Server error: ' + error);
                    console.error('AJAX Error:', status, error);
                }
            });
        });
        
        // Handle select all button
        $('#select-all').click(function() {
            $('.file-checkbox').prop('checked', true);
            $('#select-all-files').prop('checked', true);
        });
        
        // Handle deselect all button
        $('#deselect-all').click(function() {
            $('.file-checkbox').prop('checked', false);
            $('#select-all-files').prop('checked', false);
        });
        
        // Handle select all checkbox
        $('#select-all-files').change(function() {
            $('.file-checkbox').prop('checked', $(this).prop('checked'));
        });
    }
    
    /**
     * Show a message to the user
     * 
     * @param {string} type Message type: 'success', 'error', 'warning', 'info'
     * @param {string} message The message text
     */
    function showMessage(type, message) {
        // Remove any existing messages
        $('.cadssl-message').remove();
        
        // Create message element
        var $message = $('<div class="notice is-dismissible cadssl-message"></div>')
            .addClass('notice-' + type)
            .append($('<p></p>').text(message))
            .append('<button type="button" class="notice-dismiss"><span class="screen-reader-text">Dismiss this notice.</span></button>')
            .insertBefore('#cadssl-fix-permissions-form');
        
        // Handle dismiss button
        $message.find('.notice-dismiss').on('click', function() {
            $message.fadeOut(300, function() { $(this).remove(); });
        });
        
        // Automatically remove after 5 seconds
        setTimeout(function() {
            $message.fadeOut(300, function() { $(this).remove(); });
        }, 5000);
    }
})(jQuery);
