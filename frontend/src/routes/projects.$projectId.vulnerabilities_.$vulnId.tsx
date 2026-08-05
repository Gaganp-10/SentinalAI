import { useEffect } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import axios from "axios";
import { toast } from "sonner";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Download,
  Loader2,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Wand2,
} from "lucide-react";
import { DashboardShell } from "../components/dashboard/DashboardShell";
import { TopNav } from "../components/dashboard/TopNav";
import { Markdown } from "../components/project/Markdown";
import { getCurrentUser } from "../api/auth";
import { clearToken, toApiErrorMessage } from "../api/client";
import { getProject } from "../api/projects";
import {
  applyFix,
  downloadFile,
  getVulnerability,
  regenerateFix,
  setVulnerabilityFixed,
  severityTone,
} from "../api/vulnerabilities";

export const Route = createFileRoute("/projects/$projectId/vulnerabilities_/$vulnId")({
  head: () => ({
    meta: [
      { title: "Finding Detail — SentinelAI" },
      {
        name: "description",
        content:
          "Inspect a single vulnerability finding: flagged code, AI explanation, before/after fix diff, and one-click apply to the real file.",
      },
      { property: "og:title", content: "Finding Detail — SentinelAI" },
      {
        property: "og:description",
        content: "Review the diff and apply the suggested fix to your uploaded source file.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: VulnerabilityDetailPage,
});

function isUnauthorized(error: unknown) {
  return axios.isAxiosError(error) && error.response?.status === 401;
}

function Tag({ children, tone = "" }: { children: React.ReactNode; tone?: string }) {
  return (
    <span
      className={`icon-chip rounded-full px-3 py-1 text-[11.5px] uppercase tracking-[0.07em] ${
        tone || "text-muted-foreground"
      }`}
    >
      {children}
    </span>
  );
}

function DiffBlock({
  label,
  code,
  variant,
}: {
  label: string;
  code: string;
  variant: "removed" | "added";
}) {
  const removed = variant === "removed";
  return (
    <div>
      <p className="text-[11.5px] uppercase tracking-[0.08em] text-muted-foreground">{label}</p>
      <pre
        className={`mt-2 overflow-x-auto rounded-[16px] px-4 py-3 font-mono text-[12.5px] leading-[1.65] ${
          removed
            ? "bg-destructive/[0.12] text-destructive/90"
            : "bg-[oklch(0.72_0.16_150)]/[0.12] text-[oklch(0.82_0.14_150)]"
        }`}
      >
        {code.split("\n").map((line, i) => (
          <div key={i} className="whitespace-pre">
            <span className="mr-3 select-none opacity-50">{removed ? "-" : "+"}</span>
            {line}
          </div>
        ))}
      </pre>
    </div>
  );
}

function VulnerabilityDetailPage() {
  const { projectId, vulnId } = Route.useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const me = useQuery({ queryKey: ["auth", "me"], queryFn: getCurrentUser, retry: false });
  const project = useQuery({
    queryKey: ["projects", projectId],
    queryFn: () => getProject(projectId),
    retry: false,
  });
  const vuln = useQuery({
    queryKey: ["vulnerabilities", vulnId],
    queryFn: () => getVulnerability(vulnId),
    retry: false,
  });

  const authError = isUnauthorized(vuln.error) || isUnauthorized(me.error);
  useEffect(() => {
    if (authError) {
      clearToken();
      toast.error("Your session expired. Please log in again.");
      navigate({ to: "/" });
    }
  }, [authError, navigate]);

  const refresh = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["vulnerabilities", vulnId] }),
      queryClient.invalidateQueries({ queryKey: ["projects", projectId, "vulnerabilities"] }),
      queryClient.invalidateQueries({ queryKey: ["projects", projectId, "files"] }),
    ]);
  };

  const apply = useMutation({
    mutationFn: () => applyFix(vulnId),
    onSuccess: async (result) => {
      await refresh();
      toast.success(`Fix applied — file is now ${result.file.size} bytes`);
    },
    onError: (error) => {
      const message = toApiErrorMessage(error);
      const status = axios.isAxiosError(error) ? error.response?.status : undefined;
      if (status === 409) {
        const hint = /regenerat/i.test(message)
          ? ""
          : " Try regenerating the fix or edit the file manually.";
        toast.error(`This fix couldn't be applied automatically: ${message}${hint}`);
      } else {
        toast.error(message);
      }
    },
  });

  const regenerate = useMutation({
    mutationFn: () => regenerateFix(vulnId),
    onSuccess: async () => {
      await refresh();
      toast.success("Suggested fix regenerated");
    },
    onError: (error) => toast.error(toApiErrorMessage(error)),
  });

  const toggleFixed = useMutation({
    mutationFn: (fixed: boolean) => setVulnerabilityFixed(vulnId, fixed),
    onSuccess: async (updated) => {
      await refresh();
      toast.success(updated.fixed ? "Marked as fixed" : "Marked as open");
    },
    onError: (error) => toast.error(toApiErrorMessage(error)),
  });

  const download = useMutation({
    mutationFn: ({ id, filename }: { id: string; filename: string }) => downloadFile(id, filename),
    onError: (error) => toast.error(toApiErrorMessage(error)),
  });

  const data = vuln.data;
  const autoFixable = data?.auto_fixable !== false && Boolean(data?.suggested_fix);

  return (
    <DashboardShell>
      <TopNav email={me.data?.email ?? me.data?.username} />

      <main className="mx-auto w-full max-w-[1120px] px-5 pb-20 pt-8 sm:px-8">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.55, ease: [0.16, 1, 0.3, 1] }}
        >
          <nav className="flex flex-wrap items-center gap-1.5 text-[13px] text-muted-foreground">
            <Link to="/dashboard" className="transition-colors hover:text-foreground">
              Dashboard
            </Link>
            <span aria-hidden="true">›</span>
            <Link
              to="/projects/$projectId"
              params={{ projectId }}
              className="transition-colors hover:text-foreground"
            >
              {project.data?.project_name ?? "Project"}
            </Link>
            <span aria-hidden="true">›</span>
            <Link
              to="/projects/$projectId/vulnerabilities"
              params={{ projectId }}
              className="transition-colors hover:text-foreground"
            >
              Vulnerabilities
            </Link>
            <span aria-hidden="true">›</span>
            <span className="text-foreground">{data?.type ?? "Finding"}</span>
          </nav>

          <Link
            to="/projects/$projectId/vulnerabilities"
            params={{ projectId }}
            className="mt-4 inline-flex items-center gap-1.5 text-[13px] text-muted-foreground transition-colors hover:text-foreground"
          >
            <ArrowLeft className="size-[14px]" />
            Back to findings
          </Link>

          <h1 className="mt-3 text-[30px] font-semibold leading-[1.15] tracking-[-0.03em] text-foreground">
            {data?.type ?? (vuln.isLoading ? "Loading finding…" : "Finding")}
          </h1>

          {data && (
            <>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <Tag tone={severityTone(data.severity)}>{data.severity}</Tag>
                <Tag>{data.source_tool}</Tag>
                {data.cwe_id && <Tag>{data.cwe_id}</Tag>}
                {data.owasp_category && <Tag>{data.owasp_category}</Tag>}
                <Tag>{Math.round((data.confidence ?? 0) * 100)}% confidence</Tag>
              </div>
              <p className="mt-3 font-mono text-[13px] text-muted-foreground">
                {data.file?.filepath ?? data.file?.filename ?? `file ${data.file_id}`} · line{" "}
                {data.line_number}
              </p>
            </>
          )}
        </motion.div>

        {vuln.isLoading && (
          <div className="mt-7 grid gap-5 lg:grid-cols-2">
            {[0, 1].map((i) => (
              <div key={i} className="h-[260px] animate-pulse rounded-[32px] bg-foreground/[0.06]" />
            ))}
          </div>
        )}

        {vuln.isError && !authError && (
          <p role="alert" className="mt-7 text-[13.5px] text-destructive">
            {toApiErrorMessage(vuln.error)}
          </p>
        )}

        {data && (
          <>
            <div
              className={`glass-card mt-7 flex items-center gap-3 rounded-[24px] px-5 py-4 ${
                data.fixed ? "" : ""
              }`}
            >
              <span className="icon-chip flex size-[38px] shrink-0 items-center justify-center rounded-full text-foreground">
                {data.fixed ? (
                  <ShieldCheck className="size-[17px]" />
                ) : (
                  <ShieldAlert className="size-[17px]" />
                )}
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-[14.5px] font-medium text-foreground">
                  {data.fixed ? "Fixed" : "Open"}
                </p>
                <p className="mt-0.5 text-[13px] text-muted-foreground">
                  {data.fixed
                    ? "This finding is marked resolved on the backend."
                    : "This finding is still unresolved."}
                </p>
              </div>
              <button
                type="button"
                onClick={() => toggleFixed.mutate(!data.fixed)}
                disabled={toggleFixed.isPending}
                className="social-btn inline-flex shrink-0 items-center gap-2 rounded-full px-4 py-2 text-[12.5px] font-medium text-foreground disabled:opacity-45"
              >
                {toggleFixed.isPending ? (
                  <Loader2 className="size-[14px] animate-spin" />
                ) : (
                  <CheckCircle2 className="size-[14px]" />
                )}
                {data.fixed ? "Mark as open" : "Mark as fixed"}
              </button>
            </div>

            <div className="mt-5 grid items-start gap-5 lg:grid-cols-2">
              <section className="glass-card rounded-[32px] p-6 sm:p-7">
                <h2 className="text-[16px] font-semibold tracking-[-0.02em] text-foreground">
                  Flagged code
                </h2>
                <p className="mt-1.5 text-[13px] text-muted-foreground">
                  Read-only, as stored on the backend at line {data.line_number}.
                </p>
                <pre className="mt-5 overflow-x-auto rounded-[18px] bg-foreground/[0.05] px-4 py-4 font-mono text-[12.5px] leading-[1.7] text-foreground/90">
                  <code>{data.code_snippet ?? "No snippet available for this finding."}</code>
                </pre>
              </section>

              <section className="glass-card rounded-[32px] p-6 sm:p-7">
                <h2 className="text-[16px] font-semibold tracking-[-0.02em] text-foreground">
                  Explanation
                </h2>
                <div className="mt-5 space-y-5">
                  {Array.from(
                    new Set(
                      [data.description, data.explanation, data.recommendation]
                        .filter((t): t is string => Boolean(t?.trim()))
                        .map((t) => t.trim()),
                    ),
                  ).map((text) => (
                    <Markdown key={text.slice(0, 40)} text={text} />
                  ))}
                </div>
              </section>
            </div>

            <section className="glass-card mt-5 rounded-[32px] p-6 sm:p-7">
              <h2 className="text-[16px] font-semibold tracking-[-0.02em] text-foreground">
                Suggested fix
              </h2>
              <p className="mt-1.5 text-[13px] text-muted-foreground">
                Before and after, exactly as the backend would write it to the file.
              </p>

              <div className="mt-5 grid gap-4 lg:grid-cols-2">
                <DiffBlock
                  label="Current code"
                  code={data.code_snippet ?? "—"}
                  variant="removed"
                />
                <DiffBlock
                  label="Proposed code"
                  code={data.suggested_fix ?? "No suggested fix available."}
                  variant="added"
                />
              </div>

              {!autoFixable && (
                <div className="glass-field mt-5 flex items-start gap-3 rounded-[18px] px-4 py-3.5">
                  <AlertTriangle className="mt-0.5 size-[16px] shrink-0 text-[oklch(0.82_0.13_95)]" />
                  <p className="text-[13px] leading-[1.65] text-muted-foreground">
                    This finding requires manual review — no automatic fix is available for this
                    type of issue.
                  </p>
                </div>
              )}

              <div className="mt-5 flex flex-wrap gap-3">
                {autoFixable && (
                  <button
                    type="button"
                    onClick={() => apply.mutate()}
                    disabled={apply.isPending || data.fixed}
                    className="social-btn inline-flex items-center gap-2 rounded-full px-5 py-2.5 text-[13.5px] font-medium text-foreground disabled:opacity-45"
                  >
                    {apply.isPending ? (
                      <Loader2 className="size-[15px] animate-spin" />
                    ) : data.fixed ? (
                      <CheckCircle2 className="size-[15px]" />
                    ) : (
                      <Wand2 className="size-[15px]" />
                    )}
                    {data.fixed ? "Fix applied" : apply.isPending ? "Applying" : "Apply fix"}
                  </button>
                )}

                <button
                  type="button"
                  onClick={() => regenerate.mutate()}
                  disabled={regenerate.isPending}
                  className="social-btn inline-flex items-center gap-2 rounded-full px-5 py-2.5 text-[13.5px] font-medium text-foreground disabled:opacity-45"
                >
                  {regenerate.isPending ? (
                    <Loader2 className="size-[15px] animate-spin" />
                  ) : (
                    <RefreshCw className="size-[15px]" />
                  )}
                  Regenerate fix
                </button>

                <button
                  type="button"
                  onClick={() =>
                    download.mutate({
                      id: String(data.file_id),
                      filename: data.file?.filename ?? `file-${data.file_id}`,
                    })
                  }
                  disabled={download.isPending}
                  className="social-btn inline-flex items-center gap-2 rounded-full px-5 py-2.5 text-[13.5px] font-medium text-foreground disabled:opacity-45"
                >
                  {download.isPending ? (
                    <Loader2 className="size-[15px] animate-spin" />
                  ) : (
                    <Download className="size-[15px]" />
                  )}
                  Download current file
                </button>
              </div>
            </section>
          </>
        )}
      </main>
    </DashboardShell>
  );
}
