// Mobile Tutorial App JavaScript

document.addEventListener('DOMContentLoaded', function() {
    console.log('Advanced Ethical Hacking Tutorials - Application Initialized');
    
    // Initialize mobile features
    initMobileFeatures();
    initCodeCopyButtons();
    initSearchFeatures();
    initBookmarkSystem();
    initTouchGestures();
    
    // PWA support
    initPWA();
});

// Mobile-specific features
function initMobileFeatures() {
    // Prevent zoom on double tap
    let lastTouchEnd = 0;
    document.addEventListener('touchend', function(event) {
        const now = (new Date()).getTime();
        if (now - lastTouchEnd <= 300) {
            event.preventDefault();
        }
        lastTouchEnd = now;
    }, false);
    
    // Handle viewport changes
    function handleViewportChange() {
        const vh = window.innerHeight * 0.01;
        document.documentElement.style.setProperty('--vh', `${vh}px`);
    }
    
    window.addEventListener('resize', handleViewportChange);
    handleViewportChange();
    
    // Handle keyboard visibility
    const viewport = document.querySelector("meta[name=viewport]");
    function handleKeyboardVisibility() {
        if (document.activeElement.tagName === 'INPUT' || document.activeElement.tagName === 'TEXTAREA') {
            viewport.setAttribute('content', 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0');
        } else {
            viewport.setAttribute('content', 'width=device-width, initial-scale=1.0, user-scalable=no, viewport-fit=cover');
        }
    }
    
    document.addEventListener('focusin', handleKeyboardVisibility);
    document.addEventListener('focusout', handleKeyboardVisibility);
}

// Code copy functionality
function initCodeCopyButtons() {
    // Enhanced copy code function for mobile
    window.copyCode = function(button) {
        const codeContent = button.closest('.code-container').querySelector('.code-content code');
        const text = codeContent.textContent;
        
        // Use modern clipboard API with fallback
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(() => {
                showCopySuccess(button);
            }).catch(() => {
                fallbackCopyToClipboard(text, button);
            });
        } else {
            fallbackCopyToClipboard(text, button);
        }
    };
    
    function fallbackCopyToClipboard(text, button) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            showCopySuccess(button);
        } catch (err) {
            console.error('Failed to copy: ', err);
            showToast('Copy failed');
        }
        
        document.body.removeChild(textArea);
    }
    
    function showCopySuccess(button) {
        const originalHTML = button.innerHTML;
        button.innerHTML = '<i class="fas fa-check"></i> Copied!';
        button.style.background = 'var(--accent-green)';
        
        setTimeout(() => {
            button.innerHTML = originalHTML;
            button.style.background = 'var(--accent-blue)';
        }, 2000);
    }
}

// Search functionality
function initSearchFeatures() {
    // Global search function
    window.toggleSearch = function() {
        if (window.location.pathname === '/search') {
            const searchInput = document.querySelector('input[name="q"]');
            if (searchInput) {
                searchInput.focus();
            }
        } else {
            const searchSection = document.getElementById('search-section');
            if (searchSection) {
                const isVisible = searchSection.style.display !== 'none';
                if (isVisible) {
                    searchSection.style.display = 'none';
                } else {
                    searchSection.style.display = 'block';
                    document.getElementById('mobile-search-input').focus();
                }
            } else {
                window.location.href = '/search';
            }
        }
    };
    
    // Live search for home page
    const mobileSearchInput = document.getElementById('mobile-search-input');
    if (mobileSearchInput) {
        mobileSearchInput.addEventListener('input', function(e) {
            const query = e.target.value.toLowerCase();
            const tutorialCards = document.querySelectorAll('.tutorial-card');
            
            tutorialCards.forEach(card => {
                const title = card.querySelector('.tutorial-title')?.textContent.toLowerCase() || '';
                const description = card.querySelector('.tutorial-description')?.textContent.toLowerCase() || '';
                const tools = Array.from(card.querySelectorAll('.tool-tag')).map(tag => tag.textContent.toLowerCase()).join(' ');
                
                const matches = title.includes(query) || description.includes(query) || tools.includes(query);
                card.style.display = matches ? 'block' : 'none';
            });
        });
    }
}

// Bookmark system
function initBookmarkSystem() {
    window.toggleBookmarks = function() {
        const bookmarks = JSON.parse(localStorage.getItem('bookmarkedTutorials') || '[]');
        if (bookmarks.length === 0) {
            showToast('No bookmarks yet');
        } else {
            showToast(`${bookmarks.length} bookmarked tutorials`);
            // Could redirect to a bookmarks page or filter current view
        }
    };
    
    window.toggleBookmark = function() {
        const tutorialId = getCurrentTutorialId();
        if (!tutorialId) return;
        
        const bookmarks = JSON.parse(localStorage.getItem('bookmarkedTutorials') || '[]');
        
        if (bookmarks.includes(tutorialId)) {
            const index = bookmarks.indexOf(tutorialId);
            bookmarks.splice(index, 1);
            showToast('Removed from bookmarks');
        } else {
            bookmarks.push(tutorialId);
            showToast('Added to bookmarks');
        }
        
        localStorage.setItem('bookmarkedTutorials', JSON.stringify(bookmarks));
        updateBookmarkIcon(bookmarks.includes(tutorialId));
    };
    
    function getCurrentTutorialId() {
        const path = window.location.pathname;
        const match = path.match(/\/tutorial\/(.+)/);
        return match ? match[1] : null;
    }
    
    function updateBookmarkIcon(isBookmarked) {
        const bookmarkButton = document.querySelector('[onclick="toggleBookmark()"]');
        if (bookmarkButton) {
            const icon = bookmarkButton.querySelector('i');
            if (icon) {
                icon.className = isBookmarked ? 'fas fa-bookmark' : 'far fa-bookmark';
            }
        }
    }
    
    // Initialize bookmark state
    const tutorialId = getCurrentTutorialId();
    if (tutorialId) {
        const bookmarks = JSON.parse(localStorage.getItem('bookmarkedTutorials') || '[]');
        updateBookmarkIcon(bookmarks.includes(tutorialId));
    }
}

// Touch gestures
function initTouchGestures() {
    // Add touch feedback to interactive elements
    const interactiveElements = document.querySelectorAll('.tutorial-card, .mobile-card, .nav-item, button');
    
    interactiveElements.forEach(element => {
        element.addEventListener('touchstart', function() {
            this.style.transform = 'scale(0.98)';
            this.style.transition = 'transform 0.1s ease';
        });
        
        element.addEventListener('touchend', function() {
            this.style.transform = '';
        });
        
        element.addEventListener('touchcancel', function() {
            this.style.transform = '';
        });
    });
    
    // Swipe gestures for navigation
    let startX = 0;
    let startY = 0;
    
    document.addEventListener('touchstart', function(e) {
        startX = e.touches[0].clientX;
        startY = e.touches[0].clientY;
    });
    
    document.addEventListener('touchend', function(e) {
        if (!startX || !startY) return;
        
        const endX = e.changedTouches[0].clientX;
        const endY = e.changedTouches[0].clientY;
        
        const diffX = startX - endX;
        const diffY = startY - endY;
        
        // Only trigger if horizontal swipe is more significant than vertical
        if (Math.abs(diffX) > Math.abs(diffY) && Math.abs(diffX) > 50) {
            if (diffX > 0) {
                // Swipe left - could implement next tutorial
                console.log('Swipe left detected');
            } else {
                // Swipe right - could implement previous tutorial or back
                console.log('Swipe right detected');
                if (window.location.pathname !== '/') {
                    // Only go back if not on home page
                    history.back();
                }
            }
        }
        
        startX = 0;
        startY = 0;
    });
}

// Settings functionality
window.showSettings = function() {
    showToast('Settings coming soon');
    // Future: Show settings modal
};

// Toast notifications
window.showToast = function(message, duration = 2000) {
    // Remove existing toasts
    const existingToasts = document.querySelectorAll('.toast-notification');
    existingToasts.forEach(toast => toast.remove());
    
    const toast = document.createElement('div');
    toast.className = 'toast-notification';
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: var(--tertiary-bg);
        color: var(--text-primary);
        padding: 12px 24px;
        border-radius: 12px;
        border: 1px solid var(--border-color);
        z-index: 10000;
        font-size: 0.9rem;
        box-shadow: var(--card-shadow);
        animation: toastFadeIn 0.3s ease;
    `;
    
    // Add animation styles
    const style = document.createElement('style');
    style.textContent = `
        @keyframes toastFadeIn {
            from { opacity: 0; transform: translate(-50%, -50%) scale(0.8); }
            to { opacity: 1; transform: translate(-50%, -50%) scale(1); }
        }
        @keyframes toastFadeOut {
            from { opacity: 1; transform: translate(-50%, -50%) scale(1); }
            to { opacity: 0; transform: translate(-50%, -50%) scale(0.8); }
        }
    `;
    document.head.appendChild(style);
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'toastFadeOut 0.3s ease';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }, duration);
};

// PWA functionality
function initPWA() {
    // Register service worker if available
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/static/sw.js')
            .then(registration => {
                console.log('SW registered: ', registration);
            })
            .catch(registrationError => {
                console.log('SW registration failed: ', registrationError);
            });
    }
    
    // Handle install prompt
    let deferredPrompt;
    
    window.addEventListener('beforeinstallprompt', (e) => {
        e.preventDefault();
        deferredPrompt = e;
        
        // Show install button or prompt
        showInstallPrompt();
    });
    
    function showInstallPrompt() {
        // Could show a custom install prompt
        setTimeout(() => {
            showToast('Add to home screen for quick access');
        }, 3000);
    }
    
    window.addEventListener('appinstalled', () => {
        console.log('PWA was installed');
        showToast('App installed successfully!');
    });
}

// Smooth scrolling for anchor links
document.addEventListener('click', function(e) {
    if (e.target.matches('a[href^="#"]')) {
        e.preventDefault();
        const targetId = e.target.getAttribute('href');
        const targetElement = document.querySelector(targetId);
        
        if (targetElement) {
            targetElement.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    }
});

// Module navigation for tutorial pages
function initModuleNavigation() {
    const moduleLinks = document.querySelectorAll('.module-link');
    
    moduleLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                // Remove active class from all links
                moduleLinks.forEach(l => l.classList.remove('active'));
                // Add active class to clicked link
                this.classList.add('active');
                
                // Smooth scroll to target
                targetElement.scrollIntoView({ 
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Intersection Observer for auto-highlighting current section
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const moduleId = entry.target.id;
                const correspondingLink = document.querySelector(`a[href="#${moduleId}"]`);
                
                if (correspondingLink) {
                    moduleLinks.forEach(l => l.classList.remove('active'));
                    correspondingLink.classList.add('active');
                }
            }
        });
    }, {
        threshold: 0.5,
        rootMargin: '-80px 0px -80px 0px'
    });
    
    // Observe all step content elements
    document.querySelectorAll('.step-content[id]').forEach(el => {
        observer.observe(el);
    });
}

// Initialize module navigation if on tutorial page
if (document.querySelector('.module-link')) {
    initModuleNavigation();
}

// Performance monitoring
function initPerformanceMonitoring() {
    // Log page load performance
    window.addEventListener('load', () => {
        setTimeout(() => {
            const perfData = performance.getEntriesByType('navigation')[0];
            console.log('Page load time:', perfData.loadEventEnd - perfData.fetchStart, 'ms');
        }, 0);
    });
}

initPerformanceMonitoring();