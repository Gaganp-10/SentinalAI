import type { ReactNode } from "react";
import { motion } from "framer-motion";
import { ChevronLeft } from "lucide-react";
import { Link } from "@tanstack/react-router";
import authBg from "../../assets/auth-bg.jpg";
import logoImg from "../../assets/logo.png";

export function AuthShell({
  children,
  footer,
  backTo,
}: {
  children: ReactNode;
  footer?: ReactNode | undefined;
  backTo?: string | undefined;
}) {
  return (
    <main className="relative flex min-h-screen items-stretch justify-center bg-background sm:items-center sm:py-10">
      <motion.section
        initial={{ opacity: 0, y: 22, scale: 0.985 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.75, ease: [0.16, 1, 0.3, 1] }}
        className="glass-card relative flex min-h-screen w-full flex-col overflow-hidden sm:min-h-[860px] sm:max-w-[430px] sm:rounded-[46px]"
      >
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 scale-125 bg-cover bg-center blur-[34px] grayscale"
          style={{ backgroundImage: `url(${authBg})` }}
        />
        <div aria-hidden="true" className="pointer-events-none absolute inset-0 bg-[image:var(--gradient-veil)]" />
        <div aria-hidden="true" className="pattern-grain pointer-events-none absolute inset-0" />

        <div className="relative z-10 flex flex-1 flex-col px-7 pb-9 pt-14 sm:px-8">
          {backTo && (
            <motion.div
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
            >
              <Link
                to={backTo}
                aria-label="Go back"
                className="social-btn mb-8 flex size-[46px] items-center justify-center rounded-full text-foreground"
              >
                <ChevronLeft className="size-[20px]" strokeWidth={2} />
              </Link>
            </motion.div>
          )}

          {children}

          {footer && <div className="mt-auto pt-10">{footer}</div>}
        </div>
      </motion.section>
    </main>
  );
}

export function AuthHeading({ title }: { title: string }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.65, delay: 0.12, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col items-center text-center"
    >
      <div className="flex items-center gap-2.5">
        <img
          src={logoImg}
          alt="SentinelAI logo"
          className="size-8 object-contain drop-shadow-[0_2px_8px_rgba(0,0,0,0.4)]"
        />
        <span className="text-[20px] font-medium italic tracking-[-0.01em] text-foreground">
          SentinelAI
        </span>
      </div>
      <h1 className="mt-3 max-w-[290px] text-[30px] font-semibold leading-[1.18] tracking-[-0.03em] text-foreground">
        {title}
      </h1>
    </motion.div>
  );
}

export function AuthDivider({ label = "Or continue with" }: { label?: string }) {
  return (
    <div className="flex items-center gap-3">
      <span className="h-px flex-1 bg-[image:var(--gradient-rule)]" />
      <span className="text-[12.5px] font-normal tracking-[-0.01em] text-muted-foreground">
        {label}
      </span>
      <span className="h-px flex-1 bg-[image:var(--gradient-rule)]" />
    </div>
  );
}
