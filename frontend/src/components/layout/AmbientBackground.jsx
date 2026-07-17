import React, { useEffect, useRef } from 'react';

/**
 * Fixed low-opacity particle/network mesh behind the app shell.
 * pointer-events: none; respects prefers-reduced-motion.
 */
const AmbientBackground = () => {
  const canvasRef = useRef(null);
  const rafRef = useRef(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let width = 0;
    let height = 0;
    let particles = [];

    const COUNT = 48;
    const LINK_DIST = 120;
    const OPACITY = 0.06;

    const resize = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const seed = () => {
      particles = Array.from({ length: COUNT }, () => ({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.22,
        vy: (Math.random() - 0.5) * 0.22,
      }));
    };

    const drawFrame = () => {
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = `rgba(46, 204, 113, ${OPACITY + 0.02})`;
      ctx.strokeStyle = `rgba(46, 204, 113, ${OPACITY})`;
      ctx.lineWidth = 0.75;

      for (let i = 0; i < particles.length; i++) {
        const a = particles[i];
        ctx.beginPath();
        ctx.arc(a.x, a.y, 1.1, 0, Math.PI * 2);
        ctx.fill();

        for (let j = i + 1; j < particles.length; j++) {
          const b = particles[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.hypot(dx, dy);
          if (dist < LINK_DIST) {
            ctx.globalAlpha = (1 - dist / LINK_DIST) * OPACITY * 1.4;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
            ctx.globalAlpha = 1;
          }
        }
      }
    };

    const tick = () => {
      for (const p of particles) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > width) p.vx *= -1;
        if (p.y < 0 || p.y > height) p.vy *= -1;
      }
      drawFrame();
      rafRef.current = requestAnimationFrame(tick);
    };

    resize();
    seed();
    drawFrame();

    if (!reduceMotion) {
      rafRef.current = requestAnimationFrame(tick);
    }

    const onResize = () => {
      resize();
      seed();
      drawFrame();
    };
    window.addEventListener('resize', onResize);

    return () => {
      window.removeEventListener('resize', onResize);
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden
      className="fixed inset-0 z-0 pointer-events-none"
      style={{ opacity: 1 }}
    />
  );
};

export default AmbientBackground;
