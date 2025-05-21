/**
 * CADSSL Security - Advanced Headers JavaScript
 * Handles AJAX form submissions for advanced headers settings
 */
(function($) {
    'use strict';

    $(document).ready(function() {
        // Initialize form handling
        initAdvancedHeadersForm();
        
        // Toggle dependent fields based on parent field state
        setupToggleFields();
    });

    /**
     * Initialize the advanced headers form
     */
    function initAdvancedHeadersForm() {
        var $form = $('#cadssl-advanced-headers-form');
        
        // If form doesn't exist, return
        if (!$form.length) {
            return;
        }
        
        // Handle form submission
        $form.on('submit', function(e) {
            e.preventDefault();
            
            // Show saving indicator
            $('.cadssl-save-indicator').show();
            
            // Collect form data
            var formData = $form.serialize();
            
            // Send AJAX request
            $.ajax({
                url: cadssl_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'cadssl_save_advanced_headers',
                    security: cadssl_ajax.nonce,
                    form_data: formData
                },
                success: function(response) {
                    // Hide saving indicator
                    $('.cadssl-save-indicator').hide();
                    
                    if (response.success) {
                        // Show success message
                        showMessage('success', response.data.message);
                    } else {
                        // Show error message
                        showMessage('error', response.data.message || 'Error saving settings');
                        console.error('Advanced Headers Error:', response.data);
                    }
                },
                error: function(xhr, status, error) {
                    // Hide saving indicator
                    $('.cadssl-save-indicator').hide();
                    
                    // Show error message
                    showMessage('error', 'Server error: ' + error);
                    console.error('AJAX Error:', status, error);
                }
            });
        });
    }
    
    /**
     * Setup toggle fields that show/hide based on checkbox state
     */
    function setupToggleFields() {
        // Toggle CSP fields based on CSP enabled state
        $('#cadssl_advanced_headers_options_enable_csp').on('change', function() {
            var isChecked = $(this).prop('checked');
            $('.cadssl-csp-dependent').toggle(isChecked);
        }).trigger('change');
        
        // Toggle HSTS fields based on HSTS enabled state
        $('#cadssl_advanced_headers_options_enable_hsts').on('change', function() {
            var isChecked = $(this).prop('checked');
            $('.cadssl-hsts-dependent').toggle(isChecked);
        }).trigger('change');
        
        // Toggle other toggleable field sets
        $('.cadssl-field-toggle').each(function() {
            var $this = $(this);
            var targetClass = $this.data('toggle-class');
            
            $this.on('change', function() {
                var isChecked = $(this).prop('checked');
                $('.' + targetClass).toggle(isChecked);
            }).trigger('change');
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
            .insertBefore('#cadssl-advanced-headers-form');
        
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
