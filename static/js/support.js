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
        adminVideoPreview.style.width = '1000px';
        adminVideoPreview.style.height = '750px';
    }

    // Video kontrol butonlarını KESİNLİKLE SOL TARAFA ZORLA
    document.addEventListener('DOMContentLoaded', function() {
        const allButtons = document.querySelectorAll('button, [class*="button"], [class*="control"], [class*="video"], .controls, .buttons');
        allButtons.forEach(button => {
            button.style.left = '20px';
            button.style.right = 'auto';
            button.style.top = '50%';
            button.style.transform = 'translateY(-50%)';
            button.style.display = 'flex';
            button.style.flexDirection = 'column';
            button.style.gap = '15px';
            button.style.zIndex = '99999';
        });
    });
});
