import { useState, type ReactNode } from "react";
import { useNavigate } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { googleLogin, getCurrentUser } from "../../api/auth";
import { toApiErrorMessage } from "../../api/client";

declare global {
  interface Window {
    google?: {
      accounts: {
        oauth2: {
          initTokenClient: (config: {
            client_id: string;
            scope: string;
            callback: (tokenResponse: { access_token?: string; error?: string; error_description?: string }) => void;
          }) => { requestAccessToken: () => void };
        };
      };
    };
  }
}

function GoogleIcon() {
  return (
    <svg viewBox="0 0 24 24" className="size-[19px]" aria-hidden="true">
      <path
        fill="#4285F4"
        d="M23.52 12.27c0-.85-.08-1.67-.22-2.45H12v4.64h6.44a5.51 5.51 0 0 1-2.39 3.62v3h3.86c2.26-2.08 3.61-5.15 3.61-8.81z"
      />
      <path
        fill="#34A853"
        d="M12 24c3.24 0 5.96-1.08 7.95-2.92l-3.86-3c-1.07.72-2.44 1.15-4.09 1.15-3.13 0-5.78-2.11-6.72-4.96H1.29v3.1A12 12 0 0 0 12 24z"
      />
      <path fill="#FBBC05" d="M5.28 14.27a7.19 7.19 0 0 1 0-4.54v-3.1H1.29a12 12 0 0 0 0 10.74z" />
      <path
        fill="#EA4335"
        d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0A12 12 0 0 0 1.29 6.63l3.99 3.1C6.22 6.86 8.87 4.75 12 4.75z"
      />
    </svg>
  );
}

function AppleIcon() {
  return (
    <svg viewBox="0 0 24 24" className="size-[19px] fill-current" aria-hidden="true">
      <path d="M16.36 12.78c.02 2.7 2.36 3.6 2.39 3.61-.02.06-.38 1.3-1.25 2.57-.75 1.1-1.53 2.2-2.77 2.22-1.21.02-1.6-.72-2.99-.72-1.38 0-1.81.7-2.96.74-1.19.05-2.1-1.18-2.86-2.28-1.66-2.4-2.93-6.8-1.22-9.76.85-1.47 2.36-2.4 4-2.43 1.17-.02 2.27.79 2.99.79.71 0 2.05-.97 3.46-.83.59.02 2.25.21 3.31 1.62-.09.05-1.98 1.16-1.96 3.47M14.2 3.9c.64-.78 1.07-1.86.95-2.94-.92.04-2.04.61-2.7 1.38-.59.68-1.11 1.78-.97 2.83 1.03.08 2.08-.52 2.72-1.27" />
    </svg>
  );
}

function SocialButton({ children, label, onClick }: { children: ReactNode; label: string; onClick?: () => void }) {
  return (
    <motion.button
      type="button"
      onClick={onClick}
      whileHover={{ y: -2 }}
      whileTap={{ scale: 0.975, y: 0 }}
      transition={{ type: "spring", stiffness: 500, damping: 28 }}
      className="social-btn flex h-[54px] flex-1 items-center justify-center gap-2.5 rounded-full text-[15px] font-normal tracking-[-0.01em] text-foreground"
    >
      {children}
      <span className="whitespace-nowrap">{label}</span>
    </motion.button>
  );
}

export function SocialAuth() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  const handleGoogleClick = () => {
    const clientId =
      (import.meta.env["VITE_GOOGLE_CLIENT_ID"] as string | undefined) ||
      "1020864929554-v9mb9l065pedkr9ah01a1n3jsggfbc5c.apps.googleusercontent.com";

    if (!window.google?.accounts?.oauth2) {
      toast.error("Google Identity Services is loading. Please try again in a moment.");
      return;
    }

    const tokenClient = window.google.accounts.oauth2.initTokenClient({
      client_id: clientId,
      scope: "openid email profile",
      callback: async (tokenResponse) => {
        // User closed the popup or denied permission — silent no-op
        if (tokenResponse.error) {
          if (tokenResponse.error !== "access_denied" && tokenResponse.error !== "immediate_failed") {
            toast.error(`Google Sign-In failed: ${tokenResponse.error_description ?? tokenResponse.error}`);
          }
          return;
        }

        if (!tokenResponse.access_token) {
          toast.error("Google Sign-In did not return an access token. Please try again.");
          return;
        }

        setLoading(true);
        try {
          await googleLogin(tokenResponse.access_token);
          const user = await getCurrentUser();
          toast.success(`Signed in as ${user.username || user.email}`);
          navigate({ to: "/dashboard" });
        } catch (error) {
          const message = toApiErrorMessage(error);
          toast.error(message);
        } finally {
          setLoading(false);
        }
      },
    });

    tokenClient.requestAccessToken();
  };

  return (
    <div className="flex gap-3">
      <SocialButton label={loading ? "Connecting..." : "Google"} onClick={handleGoogleClick}>
        <GoogleIcon />
      </SocialButton>
      <SocialButton label="Apple" onClick={() => toast.info("Apple Sign In requires an Apple Developer account.")}>
        <AppleIcon />
      </SocialButton>
    </div>
  );
}
