// 404 Error Handler for Kova Auth
// Include this script in your main pages to handle 404 redirects

class ErrorHandler {
    constructor() {
        this.init();
    }

    init() {
        // Handle broken images
        this.handleBrokenImages();
        
        // Handle failed API calls
        this.handleFailedAPIs();
        
        // Handle navigation errors
        this.handleNavigationErrors();
    }

    // Redirect to 404 page
    redirectTo404(message = '') {
        const currentPath = encodeURIComponent(window.location.pathname);
        const searchParams = encodeURIComponent(window.location.search);
        const errorMessage = encodeURIComponent(message);
        
        window.location.href = `404.html?from=${currentPath}&query=${searchParams}&msg=${errorMessage}`;
    }

    // Handle broken images
    handleBrokenImages() {
        document.addEventListener('error', function(e) {
            if (e.target.tagName === 'IMG') {
                console.log('Broken image detected:', e.target.src);
                // You could replace with a placeholder image here
                e.target.style.display = 'none';
            }
        }, true);
    }

    // Handle failed API calls
    handleFailedAPIs() {
        // Override fetch to handle 404 responses
        const originalFetch = window.fetch;
        window.fetch = async function(...args) {
            try {
                const response = await originalFetch.apply(this, args);
                
                // If API returns 404, you might want to show a user-friendly message
                if (response.status === 404) {
                    console.log('API 404:', args[0]);
                    // Don't redirect for API calls, just log them
                }
                
                return response;
            } catch (error) {
                console.log('API Error:', error);
                throw error;
            }
        };
    }

    // Handle navigation errors
    handleNavigationErrors() {
        // Handle link clicks to non-existent pages
        document.addEventListener('click', function(e) {
            const link = e.target.closest('a');
            if (link && link.hostname === window.location.hostname) {
                const href = link.getAttribute('href');
                if (href && !href.startsWith('#') && !href.startsWith('mailto:') && !href.startsWith('tel:')) {
                    // Check if link points to a valid page
                    const validPages = [
                        'index.html',
                        'dashboard.html', 
                        'login.html',
                        'register.html',
                        'signup.html',
                        'pricing.html',
                        'docs.html',
                        'status.html'
                    ];
                    
                    const pageName = href.split('/').pop();
                    if (pageName && !validPages.includes(pageName) && pageName !== '') {
                        e.preventDefault();
                        console.log('Navigation blocked - page not found:', pageName);
                        errorHandler.redirectTo404(`Page "${pageName}" not found`);
                    }
                }
            }
        });

        // Handle JavaScript navigation errors
        window.addEventListener('error', function(e) {
            if (e.message && e.message.includes('404')) {
                console.log('JavaScript 404 error:', e.message);
            }
        });
    }

    // Check if current page should be 404
    checkPageStatus() {
        // If we're on a page that doesn't exist in your sitemap
        const currentPath = window.location.pathname;
        const validPaths = [
            '/',
            '/index.html',
            '/dashboard.html',
            '/login.html', 
            '/register.html',
            '/signup.html',
            '/pricing.html',
            '/docs.html',
            '/status.html'
        ];

        // Remove query parameters and hash
        const cleanPath = currentPath.split('?')[0].split('#')[0];
        
        if (!validPaths.includes(cleanPath) && cleanPath !== '/404.html') {
            console.log('Invalid path detected:', cleanPath);
            this.redirectTo404(`Path "${cleanPath}" not found`);
        }
    }
}

// Initialize error handler
const errorHandler = new ErrorHandler();

// Export for use in other scripts
window.ErrorHandler = ErrorHandler;
window.errorHandler = errorHandler;

// Optional: Check page status on load
// errorHandler.checkPageStatus();
