// Main JavaScript file for Cenap website

// Google Analytics Event Tracking
function trackEvent(category, action, label) {
    if (typeof gtag !== 'undefined') {
        gtag('event', action, {
            'event_category': category,
            'event_label': label
        });
    }
}

// Enhanced form validation and tracking
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return true;
    
    // Track form start if not already tracked
    if (!form.dataset.startTracked) {
        if (typeof dataLayer !== 'undefined') {
            dataLayer.push({
                'event': 'form_start',
                'form_id': formId
            });
        }
        form.dataset.startTracked = 'true';
    }
    
    const inputs = form.querySelectorAll('input[required], textarea[required], select[required]');
    let isValid = true;
    
    inputs.forEach(input => {
        if (!input.value.trim()) {
            input.classList.add('is-invalid');
            isValid = false;
        } else {
            input.classList.remove('is-invalid');
        }
    });
    
    return isValid;
}

// Image preview for file inputs
function previewImage(input) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const preview = document.getElementById('imagePreview');
            if (preview) {
                preview.src = e.target.result;
                preview.style.display = 'block';
            }
        };
        reader.readAsDataURL(input.files[0]);
    }
}

// Enhanced scroll tracking
document.addEventListener('DOMContentLoaded', function() {
    // Track scroll depth
    let scrollDepths = [25, 50, 75, 100];
    let reachedDepths = new Set();
    
    window.addEventListener('scroll', function() {
        const winHeight = window.innerHeight;
        const docHeight = document.documentElement.scrollHeight - winHeight;
        const scrolled = window.scrollY;
        const scrollPercentage = (scrolled / docHeight) * 100;
        
        scrollDepths.forEach(depth => {
            if (scrollPercentage >= depth && !reachedDepths.has(depth)) {
                reachedDepths.add(depth);
                if (typeof dataLayer !== 'undefined') {
                    dataLayer.push({
                        'event': 'scroll_depth',
                        'scroll_percent': depth
                    });
                }
            }
        });
    });

    // Smooth scrolling for anchor links
    const links = document.querySelectorAll('a[href^="#"]');
    links.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
});

// Loading state for forms
function setLoadingState(form, isLoading) {
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        if (isLoading) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Yükleniyor...';
        } else {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="fas fa-save me-2"></i>Ürün Ekle';
        }
    }
}

// Toast notification
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        const container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'position-fixed top-0 end-0 p-3';
        container.style.zIndex = '1050';
        document.body.appendChild(container);
    }
    
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    document.getElementById('toastContainer').appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}

// Auto-hide alerts
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
});

// Confirm delete with custom styling
function confirmDelete(message = 'Bu öğeyi silmek istediğinizden emin misiniz?') {
    return new Promise((resolve) => {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Onay</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <p>${message}</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">İptal</button>
                        <button type="button" class="btn btn-danger" id="confirmDelete">Sil</button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();
        
        document.getElementById('confirmDelete').addEventListener('click', () => {
            bsModal.hide();
            resolve(true);
        });
        
        modal.addEventListener('hidden.bs.modal', () => {
            modal.remove();
            resolve(false);
        });
    });
} 

function showCartSuccessMessage() {
    var msg = document.getElementById('cart-success-message');
    msg.style.display = 'block';
    setTimeout(function() {
        msg.style.display = 'none';
    }, 1200); // 1.2 saniye sonra kaybolur
} 

function sepeteEkle(btn) {
    // Butonun hemen yanındaki mesajı bul
    const successMessage = btn.nextElementSibling;
    if (successMessage && successMessage.classList.contains('cart-success-message')) {
        successMessage.style.display = 'inline';
        setTimeout(() => {
            successMessage.style.display = 'none';
        }, 1200);
    }
} 

function showGlobalCartSuccess() {
    var msg = document.getElementById('cart-global-success');
    if (msg) {
        msg.style.display = 'inline';
        setTimeout(function() {
            msg.style.display = 'none';
        }, 1200);
    }
} 

function addToCart(productId, productName, productPrice) {
    fetch('/cart/add', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            product_id: parseInt(productId),
            quantity: 1
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            updateCartCount();
            const modal = bootstrap.Modal.getInstance(document.getElementById('productDetailsModal'));
            if (modal) {
                modal.hide();
            }
            // Mesajı göster
            var modalBtn = document.getElementById('modalAddToCart');
            if (modalBtn) {
                var successMessage = modalBtn.nextElementSibling;
                if (successMessage && successMessage.classList.contains('cart-success-message')) {
                    successMessage.style.display = 'inline';
                    setTimeout(() => {
                        successMessage.style.display = 'none';
                    }, 1200);
                }
            }
            showGlobalCartSuccess(); // Sepete ekleme işlemi başarılı olduğunda global mesajı göster
        } else {
            showToast('error', data.message || 'Ürün sepete eklenirken hata oluştu.');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('error', 'Ürün sepete eklenirken hata oluştu.');
    });
} 

document.addEventListener('DOMContentLoaded', function() {
    // Video görüşme alanını ve mesajını gizle
    const videoCallArea = document.getElementById('videoCallArea');
    const callStatusText = document.getElementById('callStatusText');
    
    if (videoCallArea) {
        videoCallArea.style.display = 'none';
    }
    
    if (callStatusText) {
        callStatusText.textContent = '';
    }
    
    // Gerekirse localStorage veya sessionStorage temizle
    localStorage.removeItem('videoCallActive');
    sessionStorage.removeItem('videoCallActive');
}); 