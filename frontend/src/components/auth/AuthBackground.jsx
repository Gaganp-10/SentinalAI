import React, { useEffect, useRef } from 'react';
import { motion } from 'framer-motion';

/**
 * SentinelAI Premium Auth Background
 * - Generated PNG dark cybersecurity background
 * - Animated canvas particle network (neural mesh)
 * - Multiple layered ambient gradient orbs
 * - Fine grain noise overlay
 * - Floating geometric hex accents
 * - Respects prefers-reduced-motion
 */
const AuthBackground = () => {
  const canvasRef = useRef(null);
  const rafRef = useRef(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let w = 0;
    let h = 0;
    let particles = [];
    let time = 0;

    const PARTICLE_COUNT = 88;
    const LINK_DIST = 130;
    const BASE_OPACITY = 0.048;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = window.innerWidth;
      h = window.innerHeight;
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const seed = () => {
      particles = Array.from({ length: PARTICLE_COUNT }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        r: 0.7 + Math.random() * 1.4,
        vx: (Math.random() - 0.5) * 0.14,
        vy: (Math.random() - 0.5) * 0.14,
        pulse: Math.random() * Math.PI * 2,
        pulseSpeed: 0.008 + Math.random() * 0.016,
        type: Math.random() > 0.75 ? 'blue' : Math.random() > 0.5 ? 'indigo' : 'white',
      }));
    };

    const draw = () => {
      ctx.clearRect(0, 0, w, h);
      time += 0.004;

      for (let i = 0; i < particles.length; i++) {
        const a = particles[i];
        a.pulse += a.pulseSpeed;
        const pulseFactor = 0.85 + 0.15 * Math.sin(a.pulse);

        // Draw links first (behind dots)
        for (let j = i + 1; j < particles.length; j++) {
          const b = particles[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.hypot(dx, dy);
          if (dist < LINK_DIST) {
            const alpha = (1 - dist / LINK_DIST) * BASE_OPACITY * 1.4;
            ctx.save();
            ctx.globalAlpha = alpha;
            // Gradient line
            const grad = ctx.createLinearGradient(a.x, a.y, b.x, b.y);
            grad.addColorStop(0, 'rgba(147,197,253,1)');
            grad.addColorStop(1, 'rgba(99,102,241,1)');
            ctx.strokeStyle = grad;
            ctx.lineWidth = 0.55;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
            ctx.restore();
          }
        }

        // Draw node dot
        ctx.save();
        ctx.beginPath();
        ctx.arc(a.x, a.y, a.r * pulseFactor, 0, Math.PI * 2);
        if (a.type === 'blue') {
          ctx.fillStyle = `hsla(210, 85%, 70%, ${BASE_OPACITY * 2.8})`;
        } else if (a.type === 'indigo') {
          ctx.fillStyle = `hsla(239, 80%, 72%, ${BASE_OPACITY * 2.2})`;
        } else {
          ctx.fillStyle = `rgba(255, 255, 255, ${BASE_OPACITY * 2.0})`;
        }
        ctx.fill();
        ctx.restore();
      }
    };

    const tick = () => {
      for (const p of particles) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < -20) p.x = w + 20;
        if (p.x > w + 20) p.x = -20;
        if (p.y < -20) p.y = h + 20;
        if (p.y > h + 20) p.y = -20;
      }
      draw();
      rafRef.current = requestAnimationFrame(tick);
    };

    resize();
    seed();
    draw();

    if (!reduceMotion) {
      rafRef.current = requestAnimationFrame(tick);
    }

    const onResize = () => {
      resize();
      seed();
      draw();
    };
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, []);

  return (
    <>
      {/* Base: Generated cybersecurity background PNG */}
      <div
        aria-hidden
        className="fixed inset-0 z-0"
        style={{
          background: 'linear-gradient(145deg, #04060B 0%, #070B12 30%, #0A0E1A 60%, #080C14 100%)',
        }}
      />

      {/* Background image with subtle opacity */}
      <div
        aria-hidden
        className="fixed inset-0 z-0 pointer-events-none"
        style={{
          backgroundImage: 'url(/auth-bg.png)',
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          opacity: 0.32,
          mixBlendMode: 'luminosity',
        }}
      />

      {/* Ambient orbs — layered for depth */}
      <div
        aria-hidden
        className="fixed inset-0 z-0 pointer-events-none"
        style={{ overflow: 'hidden' }}
      >
        {/* Top-left primary blue orb */}
        <motion.div
          animate={{ scale: [1, 1.08, 1], opacity: [0.7, 1, 0.7] }}
          transition={{ duration: 9, repeat: Infinity, ease: 'easeInOut' }}
          style={{
            position: 'absolute',
            top: '-18%',
            left: '-12%',
            width: '60vw',
            height: '60vw',
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(59,130,246,0.10) 0%, transparent 68%)',
            filter: 'blur(80px)',
          }}
        />
        {/* Center-right indigo orb */}
        <motion.div
          animate={{ scale: [1, 1.12, 1], opacity: [0.6, 0.9, 0.6] }}
          transition={{ duration: 12, repeat: Infinity, ease: 'easeInOut', delay: 3 }}
          style={{
            position: 'absolute',
            top: '20%',
            right: '-10%',
            width: '44vw',
            height: '44vw',
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(99,102,241,0.08) 0%, transparent 68%)',
            filter: 'blur(100px)',
          }}
        />
        {/* Bottom-left cyan accent */}
        <motion.div
          animate={{ scale: [1, 1.06, 1], opacity: [0.5, 0.85, 0.5] }}
          transition={{ duration: 14, repeat: Infinity, ease: 'easeInOut', delay: 6 }}
          style={{
            position: 'absolute',
            bottom: '-12%',
            left: '15%',
            width: '50vw',
            height: '32vw',
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(14,165,233,0.055) 0%, transparent 70%)',
            filter: 'blur(110px)',
          }}
        />
        {/* Top-right accent */}
        <div
          style={{
            position: 'absolute',
            top: '0',
            right: '5%',
            width: '30vw',
            height: '30vw',
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(168,85,247,0.05) 0%, transparent 70%)',
            filter: 'blur(90px)',
          }}
        />
        {/* Center glow (behind card) */}
        <motion.div
          animate={{ opacity: [0.4, 0.7, 0.4] }}
          transition={{ duration: 6, repeat: Infinity, ease: 'easeInOut', delay: 1.5 }}
          style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            width: '40vw',
            height: '40vw',
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(59,130,246,0.06) 0%, transparent 70%)',
            filter: 'blur(60px)',
          }}
        />
      </div>

      {/* Particle canvas layer */}
      <canvas
        ref={canvasRef}
        aria-hidden
        className="fixed inset-0 z-0 pointer-events-none"
      />

      {/* Fine grain noise texture */}
      <div
        aria-hidden
        className="fixed inset-0 z-0 pointer-events-none"
        style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.92' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E")`,
          opacity: 0.022,
          mixBlendMode: 'overlay',
        }}
      />

      {/* Vignette overlay */}
      <div
        aria-hidden
        className="fixed inset-0 z-0 pointer-events-none"
        style={{
          background:
            'radial-gradient(ellipse at center, transparent 40%, rgba(4,6,11,0.72) 100%)',
        }}
      />
    </>
  );
};

export default AuthBackground;
