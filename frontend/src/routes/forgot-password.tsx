import { useState, useEffect } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { Mail, ArrowLeft, CheckCircle2 } from "lucide-react";
import { AuthShell, AuthHeading } from "../components/auth/AuthShell";
import { GlassField } from "../components/auth/GlassField";
import { PrimaryButton } from "../components/auth/PrimaryButton";
import { forgotPassword } from "../api/auth";
import { toApiErrorMessage } from "../api/client";

export const Route = createFileRoute("/forgot-password")({
  head: () => ({
    meta: [
      { title: "Reset Password — SentinelAI Security Platform" },
      {
        name: "description",
        content:
          "Request a secure link to reset the password for your SentinelAI security workspace.",
      },
      { property: "og:title", content: "Reset Password — SentinelAI Security Platform" },
      {
        property: "og:description",
        content: "Recover access to your SentinelAI security workspace.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ForgotPasswordPage,
});

function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | undefined>(undefined);
  const [confirmation, setConfirmation] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(0);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setInterval(() => {
      setCooldown((prev) => (prev <= 1 ? 0 : prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [cooldown]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError("Enter a valid work email address");
      return;
    }
    setError(undefined);
    setLoading(true);

    try {
      const response = await forgotPassword(email.trim());
      setConfirmation(response.message || "If an account exists for that email, we've sent a reset link.");
      setCooldown(60);
    } catch (err) {
      const message = toApiErrorMessage(err);
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell
      backTo="/"
      footer={
        <p className="text-center text-[13.5px] text-muted-foreground">
          Remember your password?{" "}
          <Link
            to="/"
            className="font-semibold text-foreground transition-opacity hover:opacity-70"
          >
            Back to login
          </Link>
        </p>
      }
    >
      <AuthHeading title="Reset Password" />

      <motion.p
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.18 }}
        className="mt-3 text-center text-[13.5px] leading-relaxed text-muted-foreground"
      >
        Enter the email associated with your account and we’ll send you a secure password reset link.
      </motion.p>

      <motion.form
        onSubmit={submit}
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.65, delay: 0.22, ease: [0.16, 1, 0.3, 1] }}
        className="mt-7 space-y-4"
      >
        <GlassField
          label="Email"
          placeholder="Enter your email"
          icon={<Mail className="size-[16px]" />}
          type="email"
          autoComplete="email"
          value={email}
          error={error}
          disabled={loading || cooldown > 0}
          onChange={(e) => {
            setEmail(e.target.value);
            if (error) setError(undefined);
          }}
        />

        <div className="pt-2">
          <PrimaryButton
            type="submit"
            loading={loading}
            disabled={loading || cooldown > 0}
          >
            {loading
              ? "Sending reset link..."
              : cooldown > 0
              ? `Resend link (${cooldown}s)`
              : "Send Reset Link"}
          </PrimaryButton>
        </div>

        {confirmation && (
          <motion.div
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-start gap-2.5 rounded-2xl border border-border/40 bg-secondary/30 p-3.5 text-[13px] text-foreground"
          >
            <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-500" />
            <div>
              <p className="font-medium text-foreground">{confirmation}</p>
              <p className="mt-1 text-[12px] text-muted-foreground">
                Please check your inbox (and spam folder). The link will expire shortly.
              </p>
            </div>
          </motion.div>
        )}
      </motion.form>
    </AuthShell>
  );
}
