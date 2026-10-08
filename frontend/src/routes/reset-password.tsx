import { useState, useEffect } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { Lock, ShieldCheck, AlertCircle, ArrowRight } from "lucide-react";
import { toast } from "sonner";
import { z } from "zod";

import { AuthShell, AuthHeading } from "../components/auth/AuthShell";
import { GlassField } from "../components/auth/GlassField";
import { PrimaryButton } from "../components/auth/PrimaryButton";
import { resetPassword } from "../api/auth";
import { toApiErrorMessage } from "../api/client";

const resetSearchSchema = z.object({
  token: z.string().optional(),
});

export const Route = createFileRoute("/reset-password")({
  validateSearch: (search: Record<string, unknown>) => resetSearchSchema.parse(search),
  head: () => ({
    meta: [
      { name: "referrer", content: "no-referrer" },
      { title: "Set New Password — SentinelAI Security Platform" },
      {
        name: "description",
        content: "Set a new secure password for your SentinelAI workspace.",
      },
      { property: "og:title", content: "Set New Password — SentinelAI Security Platform" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ResetPasswordPage,
});

function ResetPasswordPage() {
  const navigate = useNavigate();
  const search = Route.useSearch();
  const [token, setToken] = useState<string>(() => search.token || "");

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<{ password?: string; confirm?: string }>({});
  const [formError, setFormError] = useState<string | undefined>(undefined);
  const [isTokenInvalid, setIsTokenInvalid] = useState(false);

  // Immediately remove token from visible browser URL to prevent leakage
  // through copy/paste, screen shares, or browser history, while retaining it in memory.
  // Also enforce document-level Referrer-Policy: no-referrer.
  useEffect(() => {
    if (typeof window !== "undefined") {
      if (window.location.search.includes("token")) {
        window.history.replaceState({}, document.title, window.location.pathname);
      }

      let meta = document.querySelector('meta[name="referrer"]');
      if (!meta) {
        meta = document.createElement("meta");
        meta.setAttribute("name", "referrer");
        meta.setAttribute("content", "no-referrer");
        document.head.appendChild(meta);
      } else {
        meta.setAttribute("content", "no-referrer");
      }
    }
  }, []);

  const validate = (): boolean => {
    const nextErrors: typeof errors = {};

    if (!password || password.trim() === "") {
      nextErrors.password = "Password cannot be blank or whitespace only";
    } else if (password.length < 8) {
      nextErrors.password = "Password must be at least 8 characters long";
    } else if (new TextEncoder().encode(password).length > 72) {
      nextErrors.password = "Password exceeds the 72-byte limit";
    }

    if (confirmPassword !== password) {
      nextErrors.confirm = "Passwords do not match";
    }

    setErrors(nextErrors);
    return Object.keys(nextErrors).length === 0;
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(undefined);

    if (!token) {
      setIsTokenInvalid(true);
      return;
    }

    if (!validate()) return;

    setLoading(true);
    try {
      const resp = await resetPassword(token, password);
      toast.success(resp.message || "Password updated. You can now log in.");
      navigate({ to: "/" });
    } catch (err) {
      const message = toApiErrorMessage(err);
      setFormError(message);
      if (
        message.toLowerCase().includes("invalid") ||
        message.toLowerCase().includes("expired")
      ) {
        setIsTokenInvalid(true);
      }
    } finally {
      setLoading(false);
    }
  };

  // State when no token was provided in the query string
  if (!token) {
    return (
      <AuthShell
        backTo="/"
        footer={
          <p className="text-center text-[13.5px] text-muted-foreground">
            Return to{" "}
            <Link to="/" className="font-semibold text-foreground transition-opacity hover:opacity-70">
              Login
            </Link>
          </p>
        }
      >
        <AuthHeading title="Missing Reset Token" />

        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="mt-8 flex flex-col items-center text-center space-y-4"
        >
          <div className="flex size-12 items-center justify-center rounded-2xl bg-destructive/10 text-destructive border border-destructive/20">
            <AlertCircle className="size-6" />
          </div>

          <p className="text-[14px] text-muted-foreground max-w-[320px]">
            This reset link is missing a valid security token or has already been used.
          </p>

          <div className="pt-2 w-full">
            <Link
              to="/forgot-password"
              className="inline-flex w-full items-center justify-center gap-2 rounded-full bg-foreground px-5 py-3 text-[14px] font-medium text-background transition-opacity hover:opacity-90"
            >
              Request a New Link
              <ArrowRight className="size-4" />
            </Link>
          </div>
        </motion.div>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      backTo="/"
      footer={
        <p className="text-center text-[13.5px] text-muted-foreground">
          Remember your password?{" "}
          <Link to="/" className="font-semibold text-foreground transition-opacity hover:opacity-70">
            Login
          </Link>
        </p>
      }
    >
      <AuthHeading title="Set New Password" />

      <motion.p
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.18 }}
        className="mt-3 text-center text-[13.5px] leading-relaxed text-muted-foreground"
      >
        Create a new password of at least 8 characters for your workspace.
      </motion.p>

      <motion.form
        onSubmit={submit}
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.65, delay: 0.22, ease: [0.16, 1, 0.3, 1] }}
        className="mt-7 space-y-4"
      >
        <GlassField
          label="New Password"
          placeholder="Enter new password"
          icon={<Lock className="size-[16px]" />}
          isPassword
          autoComplete="new-password"
          value={password}
          error={errors.password}
          onChange={(e) => {
            setPassword(e.target.value);
            if (errors.password) setErrors((prev) => ({ ...prev, password: undefined }));
          }}
        />

        <GlassField
          label="Confirm Password"
          placeholder="Confirm new password"
          icon={<ShieldCheck className="size-[16px]" />}
          isPassword
          autoComplete="new-password"
          value={confirmPassword}
          error={errors.confirm}
          onChange={(e) => {
            setConfirmPassword(e.target.value);
            if (errors.confirm) setErrors((prev) => ({ ...prev, confirm: undefined }));
          }}
        />

        {formError && (
          <motion.div
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            className="rounded-xl border border-destructive/30 bg-destructive/10 p-3 text-[13px] text-destructive"
          >
            <p>{formError}</p>
            {isTokenInvalid && (
              <p className="mt-1.5 text-[12px] font-medium text-foreground">
                <Link to="/forgot-password" className="underline hover:opacity-80">
                  Click here to request a new reset link.
                </Link>
              </p>
            )}
          </motion.div>
        )}

        <div className="pt-2">
          <PrimaryButton type="submit" loading={loading}>
            {loading ? "Updating password..." : "Update Password"}
          </PrimaryButton>
        </div>
      </motion.form>
    </AuthShell>
  );
}
