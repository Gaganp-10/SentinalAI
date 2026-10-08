import { useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { Mail, Lock, ShieldCheck, User } from "lucide-react";
import { toast } from "sonner";
import { AuthShell, AuthHeading, AuthDivider } from "../components/auth/AuthShell";
import { GlassField } from "../components/auth/GlassField";
import { PrimaryButton } from "../components/auth/PrimaryButton";
import { SocialAuth } from "../components/auth/SocialAuth";
import { signup } from "../api/auth";
import { toApiErrorMessage } from "../api/client";

export const Route = createFileRoute("/register")({
  head: () => ({
    meta: [
      { title: "Create Account — SentinelAI Security Platform" },
      {
        name: "description",
        content:
          "Create your SentinelAI account and start detecting and auto-remediating security vulnerabilities across your codebase.",
      },
      { property: "og:title", content: "Create Account — SentinelAI Security Platform" },
      {
        property: "og:description",
        content: "Join SentinelAI for AI-powered vulnerability detection and automated remediation.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: RegisterPage,
});

function RegisterPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<{
    username?: string;
    email?: string;
    password?: string;
    confirm?: string;
  }>({});
  const [formError, setFormError] = useState<string | undefined>(undefined);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const next: typeof errors = {};
    if (username.trim().length < 3) next.username = "Use at least 3 characters";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) next.email = "Enter a valid work email address";
    if (password.trim() === "") next.password = "Password cannot be whitespace only";
    else if (password.length < 8) next.password = "Use at least 8 characters";
    else if (new TextEncoder().encode(password).length > 72) next.password = "Use at most 72 bytes";
    if (confirm !== password) next.confirm = "Passwords do not match";
    setErrors(next);
    setFormError(undefined);
    if (Object.keys(next).length) return;

    setLoading(true);
    try {
      await signup(username.trim(), email.trim(), password);
      toast.success("Account created. You can log in now.");
      navigate({ to: "/" });
    } catch (error) {
      const message = toApiErrorMessage(error);
      setFormError(message);
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell
      footer={
        <p className="text-center text-[13.5px] text-muted-foreground">
          Already have an account?{" "}
          <Link to="/" className="font-semibold text-foreground transition-opacity hover:opacity-70">
            Login
          </Link>
        </p>
      }
    >
      <AuthHeading title="Start Here, Create Your Account" />

      <motion.form
        onSubmit={submit}
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.65, delay: 0.22, ease: [0.16, 1, 0.3, 1] }}
        className="mt-8 space-y-4"
      >
        <GlassField
          label="Username"
          placeholder="Choose a username"
          icon={<User className="size-[16px]" />}
          type="text"
          autoComplete="username"
          value={username}
          error={errors.username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <GlassField
          label="Email"
          placeholder="Enter your email"
          icon={<Mail className="size-[16px]" />}
          type="email"
          autoComplete="email"
          value={email}
          error={errors.email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <GlassField
          label="Password"
          placeholder="Enter your password"
          icon={<Lock className="size-[16px]" />}
          isPassword
          autoComplete="new-password"
          value={password}
          error={errors.password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <GlassField
          label="Confirm password"
          placeholder="Confirm your password"
          icon={<ShieldCheck className="size-[16px]" />}
          isPassword
          autoComplete="new-password"
          value={confirm}
          error={errors.confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />

        {formError && <p className="px-1 pt-1 text-[13px] text-destructive">{formError}</p>}

        <div className="pt-4">
          <PrimaryButton type="submit" loading={loading}>
            {loading ? "Signing up" : "Sign Up"}
          </PrimaryButton>
        </div>
      </motion.form>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.6, delay: 0.34 }}
        className="mt-7 space-y-5"
      >
        <AuthDivider />
        <SocialAuth />
      </motion.div>
    </AuthShell>
  );
}
