// Video önizleme boyutlarını 2 katı büyütme
document.addEventListener('DOMContentLoaded', function() {
    const videoPreview = document.querySelector('.video-preview');
    if (videoPreview) {
        videoPreview.style.width = '600px';
        videoPreview.style.height = '450px';
    }

    // Admin panelindeki video önizleme için de aynı değişiklik
    const adminVideoPreview = document.querySelector('.admin-video-preview');
    if (adminVideoPreview) {
        adminVideoPreview.style.width = '600px';
        adminVideoPreview.style.height = '450px';
    }
});
