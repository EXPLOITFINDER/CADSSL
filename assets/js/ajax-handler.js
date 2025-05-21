/**
 * CADSSL Security - Common AJAX Handler
 * Provides common JavaScript functionality for CADSSL Security
 */
(function($) {
    'use strict';

    // Global error handling for all AJAX requests
    $(document).ajaxError(function(event, jqxhr, settings, thrownError) {
        if (settings.url.indexOf('cadssl') !== -1) {
            console.error('CADSSL AJAX Error:', thrownError || jqxhr.statusText);
            
            // Attempt to show user-friendly error
            try {
                var response = JSON.parse(jqxhr.responseText);
                if (response.data && response.data.message) {
                    showNotice('error', response.data.message);
                } else {
                    showNotice('error', 'Server error occurred. Please try again.');
                }
            } catch (e) {
                showNotice('error', 'Server error occurred. Please try again.');
            }
        }
    });
    
    /**
     * Show a notice to the user
     * 
     * @param {string} type Notice type: 'error', 'success', 'warning', 'info'
     * @param {string} message The message text
     */
    function showNotice(type, message) {
        var $notice = $('<div class="notice is-dismissible notice-' + type + '"><p>' + message + '</p></div>')
            .hide()
            .prependTo('.wrap')
            .slideDown();
            
        // Add dismiss button functionality
        $notice.append(
            $('<button type="button" class="notice-dismiss">' +
                '<span class="screen-reader-text">Dismiss this notice.</span>' +
              '</button>')
            .on('click.wp-dismiss-notice', function() {
                $notice.slideUp(function() {
                    $notice.remove();
                });
            })
        );
        
        // Auto dismiss after 5 seconds
        setTimeout(function() {
            $notice.slideUp(function() {
                $notice.remove();
            });
        }, 5000);
    }

    // Initialize tooltips
    $(document).ready(function() {
        $('.cadssl-tooltip-trigger').hover(
            function() {
                $(this).next('.cadssl-tooltip').fadeIn(200);
            },
            function() {
                $(this).next('.cadssl-tooltip').fadeOut(200);
            }
        );
    });

})(jQuery);
