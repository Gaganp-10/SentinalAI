import { useNavigate, Link } from "@tanstack/react-router";
import { Bell, LogOut, Search } from "lucide-react";
import { clearToken } from "../../api/client";
import logoImg from "../../assets/logo.png";

export function TopNav({ email }: { email?: string | undefined }) {
  const navigate = useNavigate();
  const initial = (email ?? "?").charAt(0).toUpperCase();

  return (
    <header className="glass-card sticky top-0 z-20 flex items-center gap-4 border-x-0 border-t-0 px-5 py-4 sm:px-8">
      <Link to="/dashboard" className="flex items-center gap-2.5 transition-opacity hover:opacity-90">
        <img
          src={logoImg}
          alt="SentinelAI logo"
          className="size-7 object-contain drop-shadow-[0_2px_6px_rgba(0,0,0,0.35)]"
        />
        <span className="text-[18px] font-medium italic tracking-[-0.01em] text-foreground">
          SentinelAI
        </span>
      </Link>

      <div className="glass-field ml-2 hidden h-[42px] flex-1 items-center gap-2 rounded-full px-4 md:flex">
        <Search className="size-[16px] shrink-0 text-muted-foreground" />
        <input
          aria-label="Search projects"
          placeholder="Search projects"
          className="min-w-0 flex-1 bg-transparent text-[14px] text-foreground outline-none placeholder:text-muted-foreground/80"
        />
      </div>

      <div className="ml-auto flex items-center gap-2.5">
        <button
          type="button"
          aria-label="Notifications"
          className="social-btn flex size-[40px] items-center justify-center rounded-full text-muted-foreground"
        >
          <Bell className="size-[17px]" />
        </button>

        <div className="social-btn flex h-[40px] items-center gap-2.5 rounded-full pl-1.5 pr-3.5">
          <span className="icon-chip flex size-[30px] items-center justify-center rounded-full text-[13px] font-semibold text-foreground">
            {initial}
          </span>
          <span className="hidden max-w-[160px] truncate text-[13px] text-muted-foreground sm:block">
            {email ?? "…"}
          </span>
        </div>

        <button
          type="button"
          onClick={() => {
            clearToken();
            navigate({ to: "/" });
          }}
          className="social-btn flex h-[40px] items-center gap-2 rounded-full px-4 text-[13px] font-medium text-foreground"
        >
          <LogOut className="size-[15px]" />
          <span className="hidden sm:inline">Log out</span>
        </button>
      </div>
    </header>
  );
}
