document.addEventListener("DOMContentLoaded", () => {
    // Smooth Scrolling for Nav Links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                
    // Viewport Toggle Logic (Desktop mode by default on mobile)
    const toggleBtn = document.getElementById('viewToggleBtn');
    const toggleIcon = document.getElementById('viewToggleIcon');
    const toggleText = document.getElementById('viewToggleText');
    const viewportMeta = document.getElementById('viewportMeta');
    
    // Only show the toggle button if the physical screen width is mobile/tablet size
    if (window.screen.width <= 992) {
        toggleBtn.style.display = 'flex';
        
        // Update button text based on current state
        const currentPref = localStorage.getItem('viewPref') || 'desktop';
        if (currentPref === 'desktop') {
            toggleIcon.textContent = '📱';
            toggleText.textContent = 'Switch to Mobile View';
        } else {
            toggleIcon.textContent = '💻';
            toggleText.textContent = 'Switch to Desktop View';
        }
        
        toggleBtn.addEventListener('click', () => {
            const currentPref = localStorage.getItem('viewPref') || 'desktop';
            if (currentPref === 'desktop') {
                localStorage.setItem('viewPref', 'mobile');
                viewportMeta.content = "width=device-width, initial-scale=1.0";
                toggleIcon.textContent = '💻';
                toggleText.textContent = 'Switch to Desktop View';
            } else {
                localStorage.setItem('viewPref', 'desktop');
                viewportMeta.content = "width=1200";
                toggleIcon.textContent = '📱';
                toggleText.textContent = 'Switch to Mobile View';
            }
        });
    }

});
            }
        
    // Viewport Toggle Logic (Desktop mode by default on mobile)
    const toggleBtn = document.getElementById('viewToggleBtn');
    const toggleIcon = document.getElementById('viewToggleIcon');
    const toggleText = document.getElementById('viewToggleText');
    const viewportMeta = document.getElementById('viewportMeta');
    
    // Only show the toggle button if the physical screen width is mobile/tablet size
    if (window.screen.width <= 992) {
        toggleBtn.style.display = 'flex';
        
        // Update button text based on current state
        const currentPref = localStorage.getItem('viewPref') || 'desktop';
        if (currentPref === 'desktop') {
            toggleIcon.textContent = '📱';
            toggleText.textContent = 'Switch to Mobile View';
        } else {
            toggleIcon.textContent = '💻';
            toggleText.textContent = 'Switch to Desktop View';
        }
        
        toggleBtn.addEventListener('click', () => {
            const currentPref = localStorage.getItem('viewPref') || 'desktop';
            if (currentPref === 'desktop') {
                localStorage.setItem('viewPref', 'mobile');
                viewportMeta.content = "width=device-width, initial-scale=1.0";
                toggleIcon.textContent = '💻';
                toggleText.textContent = 'Switch to Desktop View';
            } else {
                localStorage.setItem('viewPref', 'desktop');
                viewportMeta.content = "width=1200";
                toggleIcon.textContent = '📱';
                toggleText.textContent = 'Switch to Mobile View';
            }
        });
    }

});
    
    // Viewport Toggle Logic (Desktop mode by default on mobile)
    const toggleBtn = document.getElementById('viewToggleBtn');
    const toggleIcon = document.getElementById('viewToggleIcon');
    const toggleText = document.getElementById('viewToggleText');
    const viewportMeta = document.getElementById('viewportMeta');
    
    // Only show the toggle button if the physical screen width is mobile/tablet size
    if (window.screen.width <= 992) {
        toggleBtn.style.display = 'flex';
        
        // Update button text based on current state
        const currentPref = localStorage.getItem('viewPref') || 'desktop';
        if (currentPref === 'desktop') {
            toggleIcon.textContent = '📱';
            toggleText.textContent = 'Switch to Mobile View';
        } else {
            toggleIcon.textContent = '💻';
            toggleText.textContent = 'Switch to Desktop View';
        }
        
        toggleBtn.addEventListener('click', () => {
            const currentPref = localStorage.getItem('viewPref') || 'desktop';
            if (currentPref === 'desktop') {
                localStorage.setItem('viewPref', 'mobile');
                viewportMeta.content = "width=device-width, initial-scale=1.0";
                toggleIcon.textContent = '💻';
                toggleText.textContent = 'Switch to Desktop View';
            } else {
                localStorage.setItem('viewPref', 'desktop');
                viewportMeta.content = "width=1200";
                toggleIcon.textContent = '📱';
                toggleText.textContent = 'Switch to Mobile View';
            }
        });
    }

});

    // Glassmorphic Card Tilt Effect (Smoother for Light Theme)
    const cards = document.querySelectorAll('.feature-card');
    
    cards.forEach(card => {
        card.addEventListener('mousemove', e => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;
            
            const rotateX = ((y - centerY) / centerY) * -3;
            const rotateY = ((x - centerX) / centerX) * 3;
            
            card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-8px)`;
        
    // Viewport Toggle Logic (Desktop mode by default on mobile)
    const toggleBtn = document.getElementById('viewToggleBtn');
    const toggleIcon = document.getElementById('viewToggleIcon');
    const toggleText = document.getElementById('viewToggleText');
    const viewportMeta = document.getElementById('viewportMeta');
    
    // Only show the toggle button if the physical screen width is mobile/tablet size
    if (window.screen.width <= 992) {
        toggleBtn.style.display = 'flex';
        
        // Update button text based on current state
        const currentPref = localStorage.getItem('viewPref') || 'desktop';
        if (currentPref === 'desktop') {
            toggleIcon.textContent = '📱';
            toggleText.textContent = 'Switch to Mobile View';
        } else {
            toggleIcon.textContent = '💻';
            toggleText.textContent = 'Switch to Desktop View';
        }
        
        toggleBtn.addEventListener('click', () => {
            const currentPref = localStorage.getItem('viewPref') || 'desktop';
            if (currentPref === 'desktop') {
                localStorage.setItem('viewPref', 'mobile');
                viewportMeta.content = "width=device-width, initial-scale=1.0";
                toggleIcon.textContent = '💻';
                toggleText.textContent = 'Switch to Desktop View';
            } else {
                localStorage.setItem('viewPref', 'desktop');
                viewportMeta.content = "width=1200";
                toggleIcon.textContent = '📱';
                toggleText.textContent = 'Switch to Mobile View';
            }
        });
    }

});
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'perspective(1000px) rotateX(0) rotateY(0) translateY(0)';
        
    // Viewport Toggle Logic (Desktop mode by default on mobile)
    const toggleBtn = document.getElementById('viewToggleBtn');
    const toggleIcon = document.getElementById('viewToggleIcon');
    const toggleText = document.getElementById('viewToggleText');
    const viewportMeta = document.getElementById('viewportMeta');
    
    // Only show the toggle button if the physical screen width is mobile/tablet size
    if (window.screen.width <= 992) {
        toggleBtn.style.display = 'flex';
        
        // Update button text based on current state
        const currentPref = localStorage.getItem('viewPref') || 'desktop';
        if (currentPref === 'desktop') {
            toggleIcon.textContent = '📱';
            toggleText.textContent = 'Switch to Mobile View';
        } else {
            toggleIcon.textContent = '💻';
            toggleText.textContent = 'Switch to Desktop View';
        }
        
        toggleBtn.addEventListener('click', () => {
            const currentPref = localStorage.getItem('viewPref') || 'desktop';
            if (currentPref === 'desktop') {
                localStorage.setItem('viewPref', 'mobile');
                viewportMeta.content = "width=device-width, initial-scale=1.0";
                toggleIcon.textContent = '💻';
                toggleText.textContent = 'Switch to Desktop View';
            } else {
                localStorage.setItem('viewPref', 'desktop');
                viewportMeta.content = "width=1200";
                toggleIcon.textContent = '📱';
                toggleText.textContent = 'Switch to Mobile View';
            }
        });
    }

});
    
    // Viewport Toggle Logic (Desktop mode by default on mobile)
    const toggleBtn = document.getElementById('viewToggleBtn');
    const toggleIcon = document.getElementById('viewToggleIcon');
    const toggleText = document.getElementById('viewToggleText');
    const viewportMeta = document.getElementById('viewportMeta');
    
    // Only show the toggle button if the physical screen width is mobile/tablet size
    if (window.screen.width <= 992) {
        toggleBtn.style.display = 'flex';
        
        // Update button text based on current state
        const currentPref = localStorage.getItem('viewPref') || 'desktop';
        if (currentPref === 'desktop') {
            toggleIcon.textContent = '📱';
            toggleText.textContent = 'Switch to Mobile View';
        } else {
            toggleIcon.textContent = '💻';
            toggleText.textContent = 'Switch to Desktop View';
        }
        
        toggleBtn.addEventListener('click', () => {
            const currentPref = localStorage.getItem('viewPref') || 'desktop';
            if (currentPref === 'desktop') {
                localStorage.setItem('viewPref', 'mobile');
                viewportMeta.content = "width=device-width, initial-scale=1.0";
                toggleIcon.textContent = '💻';
                toggleText.textContent = 'Switch to Desktop View';
            } else {
                localStorage.setItem('viewPref', 'desktop');
                viewportMeta.content = "width=1200";
                toggleIcon.textContent = '📱';
                toggleText.textContent = 'Switch to Mobile View';
            }
        });
    }

});

    // Scroll Reveal Animation (Intersection Observer)
    const observerOptions = {
        threshold: 0.1,
        rootMargin: "0px 0px -50px 0px"
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        
    // Viewport Toggle Logic (Desktop mode by default on mobile)
    const toggleBtn = document.getElementById('viewToggleBtn');
    const toggleIcon = document.getElementById('viewToggleIcon');
    const toggleText = document.getElementById('viewToggleText');
    const viewportMeta = document.getElementById('viewportMeta');
    
    // Only show the toggle button if the physical screen width is mobile/tablet size
    if (window.screen.width <= 992) {
        toggleBtn.style.display = 'flex';
        
        // Update button text based on current state
        const currentPref = localStorage.getItem('viewPref') || 'desktop';
        if (currentPref === 'desktop') {
            toggleIcon.textContent = '📱';
            toggleText.textContent = 'Switch to Mobile View';
        } else {
            toggleIcon.textContent = '💻';
            toggleText.textContent = 'Switch to Desktop View';
        }
        
        toggleBtn.addEventListener('click', () => {
            const currentPref = localStorage.getItem('viewPref') || 'desktop';
            if (currentPref === 'desktop') {
                localStorage.setItem('viewPref', 'mobile');
                viewportMeta.content = "width=device-width, initial-scale=1.0";
                toggleIcon.textContent = '💻';
                toggleText.textContent = 'Switch to Desktop View';
            } else {
                localStorage.setItem('viewPref', 'desktop');
                viewportMeta.content = "width=1200";
                toggleIcon.textContent = '📱';
                toggleText.textContent = 'Switch to Mobile View';
            }
        });
    }

});
    }, observerOptions);

    document.querySelectorAll('.reveal-up').forEach((el, index) => {
        // Add a slight stagger to elements that load at the same time
        el.style.transitionDelay = `${index * 0.1}s`;
        observer.observe(el);
    
    // Viewport Toggle Logic (Desktop mode by default on mobile)
    const toggleBtn = document.getElementById('viewToggleBtn');
    const toggleIcon = document.getElementById('viewToggleIcon');
    const toggleText = document.getElementById('viewToggleText');
    const viewportMeta = document.getElementById('viewportMeta');
    
    // Only show the toggle button if the physical screen width is mobile/tablet size
    if (window.screen.width <= 992) {
        toggleBtn.style.display = 'flex';
        
        // Update button text based on current state
        const currentPref = localStorage.getItem('viewPref') || 'desktop';
        if (currentPref === 'desktop') {
            toggleIcon.textContent = '📱';
            toggleText.textContent = 'Switch to Mobile View';
        } else {
            toggleIcon.textContent = '💻';
            toggleText.textContent = 'Switch to Desktop View';
        }
        
        toggleBtn.addEventListener('click', () => {
            const currentPref = localStorage.getItem('viewPref') || 'desktop';
            if (currentPref === 'desktop') {
                localStorage.setItem('viewPref', 'mobile');
                viewportMeta.content = "width=device-width, initial-scale=1.0";
                toggleIcon.textContent = '💻';
                toggleText.textContent = 'Switch to Desktop View';
            } else {
                localStorage.setItem('viewPref', 'desktop');
                viewportMeta.content = "width=1200";
                toggleIcon.textContent = '📱';
                toggleText.textContent = 'Switch to Mobile View';
            }
        });
    }

});

    // Viewport Toggle Logic (Desktop mode by default on mobile)
    const toggleBtn = document.getElementById('viewToggleBtn');
    const toggleIcon = document.getElementById('viewToggleIcon');
    const toggleText = document.getElementById('viewToggleText');
    const viewportMeta = document.getElementById('viewportMeta');
    
    // Only show the toggle button if the physical screen width is mobile/tablet size
    if (window.screen.width <= 992) {
        toggleBtn.style.display = 'flex';
        
        // Update button text based on current state
        const currentPref = localStorage.getItem('viewPref') || 'desktop';
        if (currentPref === 'desktop') {
            toggleIcon.textContent = '📱';
            toggleText.textContent = 'Switch to Mobile View';
        } else {
            toggleIcon.textContent = '💻';
            toggleText.textContent = 'Switch to Desktop View';
        }
        
        toggleBtn.addEventListener('click', () => {
            const currentPref = localStorage.getItem('viewPref') || 'desktop';
            if (currentPref === 'desktop') {
                localStorage.setItem('viewPref', 'mobile');
                viewportMeta.content = "width=device-width, initial-scale=1.0";
                toggleIcon.textContent = '💻';
                toggleText.textContent = 'Switch to Desktop View';
            } else {
                localStorage.setItem('viewPref', 'desktop');
                viewportMeta.content = "width=1200";
                toggleIcon.textContent = '📱';
                toggleText.textContent = 'Switch to Mobile View';
            }
        });
    }

});
