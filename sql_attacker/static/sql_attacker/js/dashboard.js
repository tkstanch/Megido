// SQL Attacker Dashboard JavaScript

// Toast notification system
const Toast = {
    container: null,
    
    init() {
        if (!this.container) {
            this.container = document.createElement('div');
            this.container.className = 'toast-container';
            document.body.appendChild(this.container);
        }
    },
    
    show(message, type = 'success', duration = 3000) {
        this.init();
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icon = type === 'success' ? 'fa-check-circle' : 
                    type === 'error' ? 'fa-exclamation-circle' : 
                    'fa-info-circle';
        
        toast.innerHTML = `
            <i class="fas ${icon}"></i>
            <span>${message}</span>
        `;
        
        this.container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'slideIn 0.3s ease-out reverse';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }
};

// Copy to clipboard functionality
function copyToClipboard(text, button) {
    // Try modern Clipboard API first
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text)
            .then(() => {
                // Visual feedback
                const originalHTML = button.innerHTML;
                button.innerHTML = '✓ Copied!';
                button.classList.add('btn-success');
                button.classList.remove('btn-secondary');
                
                Toast.show('Payload copied to clipboard!', 'success');
                
                // Reset button after 2 seconds
                setTimeout(() => {
                    button.innerHTML = originalHTML;
                    button.classList.remove('btn-success');
                    button.classList.add('btn-secondary');
                }, 2000);
            })
            .catch(err => {
                Toast.show('Failed to copy payload', 'error');
                console.error('Failed to copy:', err);
            });
    } else {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        
        // Select and copy
        textarea.select();
        textarea.setSelectionRange(0, 99999); // For mobile devices
        
        try {
            document.execCommand('copy');
            
            // Visual feedback
            const originalHTML = button.innerHTML;
            button.innerHTML = '✓ Copied!';
            button.classList.add('btn-success');
            button.classList.remove('btn-secondary');
            
            Toast.show('Payload copied to clipboard!', 'success');
            
            // Reset button after 2 seconds
            setTimeout(() => {
                button.innerHTML = originalHTML;
                button.classList.remove('btn-success');
                button.classList.add('btn-secondary');
            }, 2000);
        } catch (err) {
            Toast.show('Failed to copy payload', 'error');
            console.error('Failed to copy:', err);
        } finally {
            document.body.removeChild(textarea);
        }
    }
}

// Payload search/filter functionality
function initPayloadSearch() {
    const searchInput = document.getElementById('payloadSearch');
    if (!searchInput) return;
    
    searchInput.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        const payloadCategories = document.querySelectorAll('.payload-category-content');
        let visibleCount = 0;
        
        payloadCategories.forEach(category => {
            const payloadItems = category.querySelectorAll('.flex.items-center.justify-between');
            let categoryHasVisible = false;
            
            payloadItems.forEach(item => {
                const payloadText = item.querySelector('code').textContent.toLowerCase();
                const tags = Array.from(item.querySelectorAll('.badge')).map(tag => tag.textContent.toLowerCase()).join(' ');
                
                if (payloadText.includes(searchTerm) || tags.includes(searchTerm)) {
                    item.classList.remove('hidden');
                    categoryHasVisible = true;
                    visibleCount++;
                } else {
                    item.classList.add('hidden');
                }
            });
            
            // Show/hide category based on visible items
            const categoryContainer = category.parentElement;
            if (searchTerm && !categoryHasVisible) {
                categoryContainer.classList.add('hidden');
            } else {
                categoryContainer.classList.remove('hidden');
            }
        });
        
        // Show message if no results
        let noResultsMsg = document.getElementById('noResultsMsg');
        if (visibleCount === 0 && searchTerm) {
            if (!noResultsMsg) {
                noResultsMsg = document.createElement('div');
                noResultsMsg.id = 'noResultsMsg';
                noResultsMsg.className = 'text-center py-12';
                noResultsMsg.innerHTML = `
                    <div class="text-6xl mb-4">🔍</div>
                    <h4 class="text-xl font-semibold text-gray-900 dark:text-white mb-2">No payloads found</h4>
                    <p class="text-gray-600 dark:text-gray-400">Try a different search term</p>
                `;
                document.querySelector('.tab-content#payload-library > div').appendChild(noResultsMsg);
            }
        } else if (noResultsMsg) {
            noResultsMsg.remove();
        }
    });
}

// Category collapse/expand functionality
function initCategoryToggle() {
    document.querySelectorAll('.payload-category-header').forEach(header => {
        header.addEventListener('click', function() {
            const content = this.nextElementSibling;
            const icon = this.querySelector('.collapse-icon');
            
            if (content.style.display === 'none') {
                content.style.display = 'block';
                icon.textContent = '▲';
            } else {
                content.style.display = 'none';
                icon.textContent = '▼';
            }
        });
    });
}

// Tab switching functionality
function initTabs() {
    const tabLinks = document.querySelectorAll('.tab-link');
    
    tabLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all tabs and contents
            document.querySelectorAll('.tab-link').forEach(tab => {
                tab.classList.remove('active', 'border-primary-500', 'text-primary-600', 'dark:text-primary-400');
                tab.classList.add('text-gray-600', 'dark:text-gray-400');
            });
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.add('hidden');
            });
            
            // Add active class to clicked tab and show corresponding content
            this.classList.add('active', 'border-primary-500', 'text-primary-600', 'dark:text-primary-400');
            this.classList.remove('text-gray-600', 'dark:text-gray-400');
            const targetId = this.getAttribute('data-tab-target');
            const targetContent = document.getElementById(targetId);
            if (targetContent) {
                targetContent.classList.remove('hidden');
            }
        });
    });
}

// Expandable table rows
function initExpandableRows() {
    document.querySelectorAll('.expand-row-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const targetRow = document.getElementById(targetId);
            
            if (targetRow) {
                if (targetRow.classList.contains('hidden')) {
                    targetRow.classList.remove('hidden');
                    this.querySelector('i').classList.remove('fa-chevron-down');
                    this.querySelector('i').classList.add('fa-chevron-up');
                } else {
                    targetRow.classList.add('hidden');
                    this.querySelector('i').classList.remove('fa-chevron-up');
                    this.querySelector('i').classList.add('fa-chevron-down');
                }
            }
        });
    });
}

// Keyboard shortcuts
function initKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl+K or Cmd+K to focus search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.getElementById('payloadSearch');
            if (searchInput) {
                searchInput.focus();
                Toast.show('Search activated', 'info', 1500);
            }
        }
    });
}

// Initialize dashboard on load
document.addEventListener('DOMContentLoaded', function() {
    console.log('SQL Attacker Dashboard loaded');
    
    // Initialize all features
    initPayloadSearch();
    initCategoryToggle();
    initTabs();
    initExpandableRows();
    initKeyboardShortcuts();
    
    // Show first tab by default
    const firstTab = document.querySelector('.tab-link');
    if (firstTab) {
        firstTab.click();
    }
    
    // Auto-expand all categories by default
    document.querySelectorAll('.payload-category-content').forEach(content => {
        content.style.display = 'block';
    });
    
    document.querySelectorAll('.collapse-icon').forEach(icon => {
        icon.textContent = '▲';
    });
    
    // Show welcome toast
    setTimeout(() => {
        Toast.show('Dashboard loaded successfully!', 'success', 2000);
    }, 500);
});

// Export functions for inline use
window.copyToClipboard = copyToClipboard;
window.Toast = Toast;
