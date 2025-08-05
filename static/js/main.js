// Main JavaScript for Advanced Ethical Hacking Tutorials

document.addEventListener('DOMContentLoaded', function() {
    // Initialize application
    initializeApp();
    
    // Add smooth scrolling for anchor links
    addSmoothScrolling();
    
    // Initialize copy code functionality
    initializeCopyCode();
    
    // Add search functionality enhancements
    enhanceSearch();
    
    // Initialize tooltips and animations
    initializeAnimations();
});

/**
 * Initialize the application
 */
function initializeApp() {
    console.log('Advanced Ethical Hacking Tutorials - Application Initialized');
    
    // Add loading states
    addLoadingStates();
    
    // Initialize responsive features
    initializeResponsiveFeatures();
    
    // Add keyboard shortcuts
    addKeyboardShortcuts();
}

/**
 * Add smooth scrolling for internal links
 */
function addSmoothScrolling() {
    const links = document.querySelectorAll('a[href^="#"]');
    
    links.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);
            
            if (targetElement) {
                const navbarHeight = document.querySelector('.navbar').offsetHeight;
                const elementPosition = targetElement.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - navbarHeight - 20;
                
                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
                
                // Highlight the target element briefly
                highlightElement(targetElement);
            }
        });
    });
}

/**
 * Initialize code copying functionality
 */
function initializeCopyCode() {
    // Add copy buttons to code blocks if they don't exist
    const codeBlocks = document.querySelectorAll('pre code');
    
    codeBlocks.forEach((codeBlock, index) => {
        if (!codeBlock.id) {
            codeBlock.id = `code-block-${index}`;
        }
        
        // Ensure copy button exists
        const container = codeBlock.closest('.code-block-container');
        if (container && !container.querySelector('.copy-btn')) {
            const header = container.querySelector('.code-header');
            if (header) {
                const copyBtn = document.createElement('button');
                copyBtn.className = 'btn btn-sm btn-outline-success copy-btn';
                copyBtn.innerHTML = '<i class="fas fa-copy"></i> Copy';
                copyBtn.onclick = () => copyCode(codeBlock.id);
                header.appendChild(copyBtn);
            }
        }
    });
}

/**
 * Copy code to clipboard
 * @param {string} elementId - ID of the code element to copy
 */
function copyCode(elementId) {
    const codeElement = document.getElementById(elementId);
    if (!codeElement) {
        showNotification('Code block not found', 'error');
        return;
    }
    
    const code = codeElement.textContent || codeElement.innerText;
    
    // Use the modern clipboard API if available
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(code).then(() => {
            showCopySuccess(elementId);
        }).catch(err => {
            console.error('Failed to copy: ', err);
            fallbackCopyTextToClipboard(code, elementId);
        });
    } else {
        fallbackCopyTextToClipboard(code, elementId);
    }
}

/**
 * Fallback copy method for older browsers
 * @param {string} text - Text to copy
 * @param {string} elementId - ID of the element for feedback
 */
function fallbackCopyTextToClipboard(text, elementId) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.top = '0';
    textArea.style.left = '0';
    textArea.style.position = 'fixed';
    
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        const successful = document.execCommand('copy');
        if (successful) {
            showCopySuccess(elementId);
        } else {
            showNotification('Failed to copy code', 'error');
        }
    } catch (err) {
        console.error('Fallback: Oops, unable to copy', err);
        showNotification('Copy not supported in this browser', 'error');
    }
    
    document.body.removeChild(textArea);
}

/**
 * Show copy success notification
 * @param {string} elementId - ID of the copied element
 */
function showCopySuccess(elementId) {
    const copyBtn = document.querySelector(`[onclick="copyCode('${elementId}')"]`);
    if (copyBtn) {
        const originalHTML = copyBtn.innerHTML;
        copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
        copyBtn.classList.remove('btn-outline-success');
        copyBtn.classList.add('btn-success');
        
        setTimeout(() => {
            copyBtn.innerHTML = originalHTML;
            copyBtn.classList.remove('btn-success');
            copyBtn.classList.add('btn-outline-success');
        }, 2000);
    }
    
    showNotification('Code copied to clipboard!', 'success');
}

/**
 * Enhance search functionality
 */
function enhanceSearch() {
    const searchInput = document.querySelector('input[name="q"]');
    const searchForm = document.querySelector('form[action*="search"]');
    
    if (!searchInput || !searchForm) return;
    
    // Add search suggestions
    addSearchSuggestions(searchInput);
    
    // Add real-time search validation
    searchInput.addEventListener('input', function() {
        const query = this.value.trim();
        
        if (query.length > 0 && query.length < 2) {
            this.classList.add('is-invalid');
            showSearchFeedback('Search query must be at least 2 characters long');
        } else {
            this.classList.remove('is-invalid');
            hideSearchFeedback();
        }
    });
    
    // Prevent submission of very short queries
    searchForm.addEventListener('submit', function(e) {
        const query = searchInput.value.trim();
        if (query.length > 0 && query.length < 2) {
            e.preventDefault();
            showNotification('Please enter at least 2 characters to search', 'warning');
            searchInput.focus();
        }
    });
}

/**
 * Add search suggestions
 * @param {Element} searchInput - Search input element
 */
function addSearchSuggestions(searchInput) {
    const suggestions = [
        'nmap scanning',
        'sql injection',
        'wireless cracking',
        'metasploit framework',
        'social engineering',
        'burp suite',
        'privilege escalation',
        'network reconnaissance',
        'web application testing',
        'post exploitation',
        'bloodhound',
        'aircrack-ng',
        'gobuster',
        'hashcat'
    ];
    
    // Create suggestions container
    const suggestionsContainer = document.createElement('div');
    suggestionsContainer.className = 'search-suggestions-dropdown';
    suggestionsContainer.style.cssText = `
        position: absolute;
        top: 100%;
        left: 0;
        right: 0;
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        border-top: none;
        border-radius: 0 0 8px 8px;
        max-height: 200px;
        overflow-y: auto;
        z-index: 1000;
        display: none;
    `;
    
    // Position the search input container relatively
    const inputGroup = searchInput.closest('.input-group') || searchInput.parentElement;
    if (inputGroup) {
        inputGroup.style.position = 'relative';
        inputGroup.appendChild(suggestionsContainer);
    }
    
    searchInput.addEventListener('input', function() {
        const query = this.value.toLowerCase().trim();
        
        if (query.length < 2) {
            suggestionsContainer.style.display = 'none';
            return;
        }
        
        const filteredSuggestions = suggestions.filter(suggestion => 
            suggestion.toLowerCase().includes(query)
        ).slice(0, 5);
        
        if (filteredSuggestions.length > 0) {
            suggestionsContainer.innerHTML = filteredSuggestions.map(suggestion => 
                `<div class="suggestion-item" style="padding: 0.75rem; cursor: pointer; border-bottom: 1px solid var(--border-color);" 
                     onmouseover="this.style.backgroundColor='rgba(88, 166, 255, 0.1)'" 
                     onmouseout="this.style.backgroundColor='transparent'"
                     onclick="selectSuggestion('${suggestion}')">${suggestion}</div>`
            ).join('');
            suggestionsContainer.style.display = 'block';
        } else {
            suggestionsContainer.style.display = 'none';
        }
    });
    
    // Hide suggestions when clicking outside
    document.addEventListener('click', function(e) {
        if (!inputGroup.contains(e.target)) {
            suggestionsContainer.style.display = 'none';
        }
    });
}

/**
 * Select a search suggestion
 * @param {string} suggestion - Selected suggestion
 */
function selectSuggestion(suggestion) {
    const searchInput = document.querySelector('input[name="q"]');
    if (searchInput) {
        searchInput.value = suggestion;
        searchInput.form.submit();
    }
}

/**
 * Show search feedback
 * @param {string} message - Feedback message
 */
function showSearchFeedback(message) {
    hideSearchFeedback(); // Remove any existing feedback
    
    const searchInput = document.querySelector('input[name="q"]');
    if (!searchInput) return;
    
    const feedback = document.createElement('div');
    feedback.className = 'invalid-feedback';
    feedback.textContent = message;
    feedback.style.display = 'block';
    
    searchInput.parentElement.appendChild(feedback);
}

/**
 * Hide search feedback
 */
function hideSearchFeedback() {
    const feedback = document.querySelector('.invalid-feedback');
    if (feedback) {
        feedback.remove();
    }
}

/**
 * Initialize animations and visual enhancements
 */
function initializeAnimations() {
    // Add fade-in animation to cards when they come into view
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);
    
    // Observe tutorial cards and feature boxes
    const elements = document.querySelectorAll('.tutorial-card, .feature-box, .tutorial-step, .search-result-card');
    elements.forEach(el => {
        observer.observe(el);
    });
    
    // Add typing effect to hero text (if on home page)
    const heroTitle = document.querySelector('.hero-section .display-4');
    if (heroTitle && !heroTitle.dataset.animated) {
        addTypingEffect(heroTitle);
        heroTitle.dataset.animated = 'true';
    }
}

/**
 * Add typing effect to an element
 * @param {Element} element - Element to animate
 */
function addTypingEffect(element) {
    const text = element.textContent;
    element.textContent = '';
    element.style.borderRight = '2px solid var(--success-color)';
    
    let i = 0;
    const timer = setInterval(() => {
        if (i < text.length) {
            element.textContent += text.charAt(i);
            i++;
        } else {
            clearInterval(timer);
            setTimeout(() => {
                element.style.borderRight = 'none';
            }, 1000);
        }
    }, 50);
}

/**
 * Add loading states to buttons and forms
 */
function addLoadingStates() {
    // Add loading state to form submissions
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn && !submitBtn.disabled) {
                const originalHTML = submitBtn.innerHTML;
                submitBtn.innerHTML = '<span class="loading-spinner"></span> Searching...';
                submitBtn.disabled = true;
                
                // Re-enable after 5 seconds (fallback)
                setTimeout(() => {
                    submitBtn.innerHTML = originalHTML;
                    submitBtn.disabled = false;
                }, 5000);
            }
        });
    });
}

/**
 * Initialize responsive features
 */
function initializeResponsiveFeatures() {
    // Collapse navigation on mobile after clicking a link
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    const navbarCollapse = document.querySelector('.navbar-collapse');
    
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            if (window.innerWidth < 992 && navbarCollapse.classList.contains('show')) {
                const bsCollapse = new bootstrap.Collapse(navbarCollapse);
                bsCollapse.hide();
            }
        });
    });
    
    // Adjust code block font size on mobile
    adjustCodeBlocksForMobile();
    
    // Handle window resize
    window.addEventListener('resize', debounce(() => {
        adjustCodeBlocksForMobile();
    }, 250));
}

/**
 * Adjust code blocks for mobile devices
 */
function adjustCodeBlocksForMobile() {
    const codeBlocks = document.querySelectorAll('pre code');
    const isMobile = window.innerWidth < 768;
    
    codeBlocks.forEach(block => {
        if (isMobile) {
            block.style.fontSize = '0.75rem';
            block.style.lineHeight = '1.4';
        } else {
            block.style.fontSize = '0.875rem';
            block.style.lineHeight = '1.6';
        }
    });
}

/**
 * Add keyboard shortcuts
 */
function addKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + K for search focus
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.querySelector('input[name="q"]');
            if (searchInput) {
                searchInput.focus();
                searchInput.select();
            }
        }
        
        // ESC to close search suggestions
        if (e.key === 'Escape') {
            const suggestions = document.querySelector('.search-suggestions-dropdown');
            if (suggestions) {
                suggestions.style.display = 'none';
            }
        }
    });
}

/**
 * Highlight an element temporarily
 * @param {Element} element - Element to highlight
 */
function highlightElement(element) {
    element.style.transition = 'all 0.3s ease';
    element.style.backgroundColor = 'rgba(88, 166, 255, 0.2)';
    element.style.transform = 'scale(1.02)';
    
    setTimeout(() => {
        element.style.backgroundColor = '';
        element.style.transform = '';
    }, 1000);
}

/**
 * Show notification message
 * @param {string} message - Notification message
 * @param {string} type - Notification type (success, error, warning, info)
 */
function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.custom-notification');
    existingNotifications.forEach(notification => notification.remove());
    
    const notification = document.createElement('div');
    notification.className = `custom-notification alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show`;
    notification.style.cssText = `
        position: fixed;
        top: 100px;
        right: 20px;
        z-index: 9999;
        min-width: 300px;
        max-width: 400px;
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
    `;
    
    const icons = {
        success: 'fas fa-check-circle',
        error: 'fas fa-exclamation-circle',
        warning: 'fas fa-exclamation-triangle',
        info: 'fas fa-info-circle'
    };
    
    notification.innerHTML = `
        <i class="${icons[type] || icons.info}"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

/**
 * Scroll to top of page
 */
function scrollToTop() {
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
}

/**
 * Debounce function to limit function calls
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Make functions globally available
window.copyCode = copyCode;
window.selectSuggestion = selectSuggestion;
window.scrollToTop = scrollToTop;
