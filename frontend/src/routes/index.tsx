import { useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { User, Lock, Check } from "lucide-react";
import { toast } from "sonner";
import { AuthShell, AuthHeading, AuthDivider } from "../components/auth/AuthShell";
import { GlassField } from "../components/auth/GlassField";
import { PrimaryButton } from "../components/auth/PrimaryButton";
import { SocialAuth } from "../components/auth/SocialAuth";
import { login, getCurrentUser } from "../api/auth";
import { toApiErrorMessage } from "../api/client";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Log In — SentinelAI Security Platform" },
      {
        name: "description",
        content:
          "Log in to SentinelAI, the AI-powered security vulnerability detection and auto remediation platform for enterprise engineering teams.",
      },
      { property: "og:title", content: "Log In — SentinelAI Security Platform" },
      {
        property: "og:description",
        content:
          "Access your SentinelAI workspace for AI-powered vulnerability detection and automated remediation.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: LoginPage,
});

function LoginPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<{ username?: string; password?: string }>({});
  const [formError, setFormError] = useState<string | undefined>(undefined);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const next: typeof errors = {};
    if (username.trim().length < 3) next.username = "Enter your username";
    if (password.length < 1) next.password = "Enter your password";
    setErrors(next);
    setFormError(undefined);
    if (Object.keys(next).length) return;

    setLoading(true);
    try {
      await login(username.trim(), password);
      const user = await getCurrentUser();
      toast.success(`Signed in as ${user.username ?? username.trim()}`);
      navigate({ to: "/dashboard" });
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
          Don&apos;t have an account?{" "}
          <Link
            to="/register"
            className="font-semibold text-foreground transition-opacity hover:opacity-70"
          >
            Create an account
          </Link>
        </p>
      }
    >
      <AuthHeading title="Log In, Secure Your Code" />

      <motion.form
        onSubmit={submit}
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.65, delay: 0.22, ease: [0.16, 1, 0.3, 1] }}
        className="mt-9 space-y-4"
      >
        <GlassField
          label="Username"
          placeholder="Enter your username"
          icon={<User className="size-[16px]" />}
          type="text"
          autoComplete="username"
          value={username}
          error={errors.username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <GlassField
          label="Password"
          placeholder="Enter your password"
          icon={<Lock className="size-[16px]" />}
          isPassword
          autoComplete="current-password"
          value={password}
          error={errors.password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <div className="flex items-center justify-between px-1 pt-1">
          <button
            type="button"
            onClick={() => setRemember((v) => !v)}
            className="flex items-center gap-2.5 text-[13.5px] font-normal text-muted-foreground transition-colors hover:text-foreground"
          >
            <motion.span
              animate={{
                backgroundColor: remember ? "oklch(1 0 0 / 92%)" : "oklch(1 0 0 / 8%)",
                borderColor: remember ? "oklch(1 0 0 / 92%)" : "oklch(1 0 0 / 24%)",
              }}
              transition={{ duration: 0.22 }}
              className="flex size-[20px] items-center justify-center rounded-[7px] border"
            >
              <motion.span
                initial={false}
                animate={{ scale: remember ? 1 : 0, opacity: remember ? 1 : 0 }}
                transition={{ type: "spring", stiffness: 520, damping: 26 }}
              >
                <Check className="size-[13px] text-background" strokeWidth={3.2} />
              </motion.span>
            </motion.span>
            Remember me
          </button>

          <Link
            to="/forgot-password"
            className="text-[13.5px] font-normal text-muted-foreground transition-colors hover:text-foreground"
          >
            Forgot Password?
          </Link>
        </div>

        {formError && (
          <p className="px-1 pt-1 text-[13px] text-destructive">{formError}</p>
        )}

        <div className="pt-4">
          <PrimaryButton type="submit" loading={loading}>
            {loading ? "Logging in" : "Login"}
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
