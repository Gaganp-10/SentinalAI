import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { AuthShell, AuthHeading } from "../components/auth/AuthShell";
import { PrimaryButton } from "../components/auth/PrimaryButton";
import { getCurrentUser } from "../api/auth";
import { clearToken, toApiErrorMessage } from "../api/client";

export const Route = createFileRoute("/account")({
  head: () => ({
    meta: [
      { title: "Your Account — SentinelAI Security Platform" },
      {
        name: "description",
        content:
          "View the authenticated SentinelAI account details returned by the security backend for your session.",
      },
      { property: "og:title", content: "Your Account — SentinelAI Security Platform" },
      {
        property: "og:description",
        content: "Authenticated SentinelAI session details from the security backend.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: AccountPage,
});

function AccountPage() {
  const navigate = useNavigate();
  const { data, error, isLoading } = useQuery({
    queryKey: ["auth", "me"],
    queryFn: getCurrentUser,
    retry: false,
  });

  return (
    <AuthShell backTo="/">
      <AuthHeading title="Your Authenticated Session" />

      <div className="mt-8 space-y-4">
        {isLoading && <p className="text-[14px] text-muted-foreground">Loading your account…</p>}

        {error && (
          <p className="text-[13.5px] text-destructive">
            Could not load your account: {toApiErrorMessage(error)}
          </p>
        )}

        {data && (
          <pre className="glass-card overflow-x-auto rounded-3xl p-5 text-[12.5px] leading-relaxed text-foreground">
            {JSON.stringify(data, null, 2)}
          </pre>
        )}

        <div className="pt-3">
          <PrimaryButton
            type="button"
            onClick={() => {
              clearToken();
              navigate({ to: "/" });
            }}
          >
            Log out
          </PrimaryButton>
        </div>
      </div>
    </AuthShell>
  );
}
