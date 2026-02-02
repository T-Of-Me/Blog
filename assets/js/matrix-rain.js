// Matrix Rain Effect for Hugo Stack Theme
(function() {
    'use strict';
    
    // Wait for DOM
    function initMatrix() {
        // Create canvas
        const canvas = document.createElement('canvas');
        canvas.id = 'matrix-canvas';
        canvas.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;opacity:0.8;pointer-events:none';
        
        // Insert at beginning of body
        if (document.body.firstChild) {
            document.body.insertBefore(canvas, document.body.firstChild);
        } else {
            document.body.appendChild(canvas);
        }
        
        const ctx = canvas.getContext('2d');
        
        // Set size
        let w = canvas.width = window.innerWidth;
        let h = canvas.height = window.innerHeight;
        
        // Characters - Katakana, Latin, Numbers
        const chars = 'アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズブヅプエェケセテネヘメレヱゲゼデベペオォコソトノホモヨョロヲゴゾドボポヴッンABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        const fontSize = 16;
        let cols = Math.floor(w / fontSize);
        const drops = [];
        
        // Initialize drops
        for (let i = 0; i < cols; i++) {
            drops[i] = Math.floor(Math.random() * h / fontSize);
        }
        
        // Draw function
        function draw() {
            // Black background with fade
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, w, h);
            
            // Green text
            ctx.fillStyle = '#0F0';
            ctx.font = fontSize + 'px monospace';
            
            // Draw characters
            for (let i = 0; i < drops.length; i++) {
                const text = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                
                // Reset drop
                if (drops[i] * fontSize > h && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }
        
        // Animation loop
        setInterval(draw, 30);
        
        // Resize handler
        window.addEventListener('resize', function() {
            w = canvas.width = window.innerWidth;
            h = canvas.height = window.innerHeight;
            cols = Math.floor(w / fontSize);
            drops.length = cols;
            for (let i = 0; i < cols; i++) {
                drops[i] = Math.floor(Math.random() * h / fontSize);
            }
        });
    }
    
    // Execute when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initMatrix);
    } else {
        initMatrix();
    }
})();