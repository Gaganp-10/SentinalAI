import type { ReactNode } from "react";
import authBg from "../../assets/auth-bg.jpg";

export function DashboardShell({ children }: { children: ReactNode }) {
  return (
    <div className="relative min-h-screen overflow-hidden bg-background">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 scale-125 bg-cover bg-center opacity-60 blur-[60px] grayscale"
        style={{ backgroundImage: `url(${authBg})` }}
      />
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 bg-[image:var(--gradient-veil)]" />
      <div aria-hidden="true" className="pattern-grain pointer-events-none absolute inset-0" />
      <div className="relative z-10">{children}</div>
    </div>
  );
}
