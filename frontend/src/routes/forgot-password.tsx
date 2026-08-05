import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { Mail } from "lucide-react";
import { AuthShell, AuthHeading } from "../components/auth/AuthShell";
import { GlassField } from "../components/auth/GlassField";
import { PrimaryButton } from "../components/auth/PrimaryButton";

export const Route = createFileRoute("/forgot-password")({
  head: () => ({
    meta: [
      { title: "Reset Password — SentinelAI Security Platform" },
      {
        name: "description",
        content:
          "Request a verification code to reset the password for your SentinelAI security workspace.",
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
  const [sent, setSent] = useState(false);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError("Enter a valid work email address");
      return;
    }
    setError(undefined);
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
      setSent(true);
    }, 1400);
  };

  return (
    <AuthShell backTo="/">
      <AuthHeading title="Reset Password To Continue Using" />

      <motion.form
        onSubmit={submit}
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.65, delay: 0.22, ease: [0.16, 1, 0.3, 1] }}
        className="mt-9 space-y-4"
      >
        <GlassField
          label="Email"
          placeholder="Enter your email"
          icon={<Mail className="size-[16px]" />}
          type="email"
          autoComplete="email"
          value={email}
          error={error}
          onChange={(e) => setEmail(e.target.value)}
        />

        <div className="pt-3">
          <PrimaryButton type="submit" loading={loading}>
            {loading ? "Sending code" : "Send Code"}
          </PrimaryButton>
        </div>

        {sent && (
          <motion.p
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            className="pt-1 text-center text-[13px] text-muted-foreground"
          >
            Verification code sent. Check your inbox.
          </motion.p>
        )}
      </motion.form>
    </AuthShell>
  );
}
