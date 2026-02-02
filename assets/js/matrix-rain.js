// Matrix Rain Effect - Matrix Digital Rain Animation
(function() {
    'use strict';
    
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initMatrix);
    } else {
        initMatrix();
    }
    
    function initMatrix() {
        // Tạo canvas element
        const canvas = document.createElement('canvas');
        canvas.id = 'matrix-canvas';
        canvas.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;opacity:0.8;pointer-events:none;';
        
        // Insert vào đầu body
        if (document.body.firstChild) {
            document.body.insertBefore(canvas, document.body.firstChild);
        } else {
            document.body.appendChild(canvas);
        }
        
        const ctx = canvas.getContext('2d');
        
        // Set canvas size
        let w = canvas.width = window.innerWidth;
        let h = canvas.height = window.innerHeight;
        
        // Characters - Katakana, Latin, Numbers
        const katakana = 'アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズブヅプエェケセテネヘメレヱゲゼデベペオォコソトノホモヨョロヲゴゾドボポヴッン';
        const latin = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const nums = '0123456789';
        const alphabet = katakana + latin + nums;
        
        const fontSize = 16;
        let columns = Math.floor(w / fontSize);
        
        // Rain drops array
        const rainDrops = [];
        
        // Initialize rain drops
        for (let x = 0; x < columns; x++) {
            rainDrops[x] = Math.floor(Math.random() * h / fontSize);
        }
        
        // Draw function
        const draw = () => {
            // Semi-transparent black để tạo fade effect
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, w, h);
            
            // Green text
            ctx.fillStyle = '#0F0';
            ctx.font = fontSize + 'px monospace';
            
            // Draw characters
            for (let i = 0; i < rainDrops.length; i++) {
                // Random character
                const text = alphabet.charAt(Math.floor(Math.random() * alphabet.length));
                const x = i * fontSize;
                const y = rainDrops[i] * fontSize;
                
                ctx.fillText(text, x, y);
                
                // Reset drop randomly hoặc khi chạm đáy
                if (y > h && Math.random() > 0.975) {
                    rainDrops[i] = 0;
                }
                
                rainDrops[i]++;
            }
        };
        
        // Animation interval
        const interval = setInterval(draw, 30);
        
        // Resize handler
        window.addEventListener('resize', () => {
            w = canvas.width = window.innerWidth;
            h = canvas.height = window.innerHeight;
            columns = Math.floor(w / fontSize);
            
            // Reinitialize drops
            rainDrops.length = 0;
            for (let x = 0; x < columns; x++) {
                rainDrops[x] = Math.floor(Math.random() * h / fontSize);
            }
        });
        
        // Cleanup on page unload
        window.addEventListener('beforeunload', () => {
            clearInterval(interval);
        });
    }
})();