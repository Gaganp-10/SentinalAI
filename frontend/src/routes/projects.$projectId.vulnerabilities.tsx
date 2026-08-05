import { useEffect, useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { ArrowLeft, Download, ShieldAlert } from "lucide-react";
import axios from "axios";
import { toast } from "sonner";
import { DashboardShell } from "../components/dashboard/DashboardShell";
import { TopNav } from "../components/dashboard/TopNav";
import { VulnerabilityCard } from "../components/project/VulnerabilityCard";
import { getCurrentUser } from "../api/auth";
import { clearToken, toApiErrorMessage } from "../api/client";
import { getProject } from "../api/projects";
import { listFiles } from "../api/files";
import {
  applyFix,
  downloadFile,
  listVulnerabilities,
  regenerateFix,
  SEVERITY_ORDER,
  severityTone,
} from "../api/vulnerabilities";

export const Route = createFileRoute("/projects/$projectId/vulnerabilities")({
  head: () => ({
    meta: [
      { title: "Findings & Fixes — SentinelAI" },
      {
        name: "description",
        content:
          "Review real vulnerability findings, inspect AI-suggested fixes, apply them to the uploaded file, and download the patched source.",
      },
      { property: "og:title", content: "Findings & Fixes — SentinelAI" },
      {
        property: "og:description",
        content: "Detailed vulnerability findings and one-click fix application for your project.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: VulnerabilitiesPage,
});

function isUnauthorized(error: unknown) {
  return axios.isAxiosError(error) && error.response?.status === 401;
}

function VulnerabilitiesPage() {
  const { projectId } = Route.useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [severity, setSeverity] = useState<string | null>(null);
  const [applyingId, setApplyingId] = useState<string | null>(null);
  const [regeneratingId, setRegeneratingId] = useState<string | null>(null);

  const me = useQuery({ queryKey: ["auth", "me"], queryFn: getCurrentUser, retry: false });
  const project = useQuery({
    queryKey: ["projects", projectId],
    queryFn: () => getProject(projectId),
    retry: false,
  });
  const files = useQuery({
    queryKey: ["projects", projectId, "files"],
    queryFn: () => listFiles(projectId),
    retry: false,
  });
  const vulns = useQuery({
    queryKey: ["projects", projectId, "vulnerabilities", severity],
    queryFn: () => listVulnerabilities(projectId, severity ? { severity } : undefined),
    retry: false,
  });

  const authError = isUnauthorized(vulns.error) || isUnauthorized(me.error);
  useEffect(() => {
    if (authError) {
      clearToken();
      toast.error("Your session expired. Please log in again.");
      navigate({ to: "/" });
    }
  }, [authError, navigate]);

  const apply = useMutation({
    mutationFn: (vulnId: string) => applyFix(vulnId),
    onMutate: (vulnId) => setApplyingId(vulnId),
    onSettled: () => setApplyingId(null),
    onSuccess: async (result) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["projects", projectId, "vulnerabilities"] }),
        queryClient.invalidateQueries({ queryKey: ["projects", projectId, "files"] }),
      ]);
      toast.success(`Fix applied — file is now ${result.file.size} bytes`);
    },
    onError: (error) => toast.error(toApiErrorMessage(error)),
  });

  const regenerate = useMutation({
    mutationFn: (vulnId: string) => regenerateFix(vulnId),
    onMutate: (vulnId) => setRegeneratingId(vulnId),
    onSettled: () => setRegeneratingId(null),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ["projects", projectId, "vulnerabilities"],
      });
      toast.success("Suggested fix regenerated");
    },
    onError: (error) => toast.error(toApiErrorMessage(error)),
  });

  const download = useMutation({
    mutationFn: ({ id, filename }: { id: string; filename: string }) => downloadFile(id, filename),
    onError: (error) => toast.error(toApiErrorMessage(error)),
  });

  const list = vulns.data ?? [];
  const counts = SEVERITY_ORDER.map((key) => ({
    key,
    count: list.filter((v) => v.severity.toLowerCase() === key).length,
  }));
  const fileList = files.data ?? [];

  return (
    <DashboardShell>
      <TopNav email={me.data?.email ?? me.data?.username} />

      <main className="mx-auto w-full max-w-[880px] px-5 pb-20 pt-8 sm:px-8">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.55, ease: [0.16, 1, 0.3, 1] }}
        >
          <Link
            to="/projects/$projectId"
            params={{ projectId }}
            className="inline-flex items-center gap-1.5 text-[13px] text-muted-foreground transition-colors hover:text-foreground"
          >
            <ArrowLeft className="size-[14px]" />
            Upload & scan
          </Link>

          <h1 className="mt-3 text-[30px] font-semibold leading-[1.15] tracking-[-0.03em] text-foreground">
            Findings
          </h1>
          <p className="mt-2 text-[14px] text-muted-foreground">
            {project.data?.project_name ?? "Project"} — review each finding, apply the suggested fix
            to the real file, then download the patched source.
          </p>
        </motion.div>

        <section className="glass-card mt-7 rounded-[32px] p-6 sm:p-7">
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={() => setSeverity(null)}
              className={`social-btn rounded-full px-4 py-2 text-[12.5px] font-medium text-foreground ${
                severity === null ? "" : "opacity-60"
              }`}
            >
              All ({list.length})
            </button>
            {counts.map((c) => (
              <button
                key={c.key}
                type="button"
                onClick={() => setSeverity(c.key)}
                className={`social-btn rounded-full px-4 py-2 text-[12.5px] font-medium capitalize ${
                  severity === c.key ? "" : "opacity-60"
                } ${severityTone(c.key)}`}
              >
                {c.key} ({c.count})
              </button>
            ))}
          </div>

          {vulns.isLoading && (
            <div className="mt-6 space-y-3">
              {[0, 1, 2].map((i) => (
                <div
                  key={i}
                  className="h-[76px] animate-pulse rounded-[22px] bg-foreground/[0.06]"
                />
              ))}
            </div>
          )}

          {vulns.isError && !authError && (
            <p role="alert" className="mt-5 text-[13.5px] text-destructive">
              {toApiErrorMessage(vulns.error)}
            </p>
          )}

          {!vulns.isLoading && !vulns.isError && list.length === 0 && (
            <div className="mt-6 flex flex-col items-center py-10 text-center">
              <span className="icon-chip flex size-[48px] items-center justify-center rounded-full text-foreground">
                <ShieldAlert className="size-[20px]" />
              </span>
              <p className="mt-4 text-[15px] font-medium text-foreground">No findings to show</p>
              <p className="mt-1.5 text-[13.5px] text-muted-foreground">
                Run a scan on this project, or clear the severity filter.
              </p>
            </div>
          )}

          {list.length > 0 && (
            <ul className="mt-6 space-y-3">
              {list.map((vuln, i) => (
                <VulnerabilityCard
                  key={String(vuln.id)}
                  vuln={vuln}
                  projectId={projectId}
                  index={i}
                  applying={applyingId === String(vuln.id) && apply.isPending}
                  regenerating={regeneratingId === String(vuln.id) && regenerate.isPending}
                  onApply={() => apply.mutate(String(vuln.id))}
                  onRegenerate={() => regenerate.mutate(String(vuln.id))}
                />
              ))}
            </ul>
          )}
        </section>

        {fileList.length > 0 && (
          <section className="glass-card mt-6 rounded-[32px] p-6 sm:p-7">
            <h2 className="text-[16px] font-semibold tracking-[-0.02em] text-foreground">
              Download current files
            </h2>
            <p className="mt-1.5 text-[13.5px] text-muted-foreground">
              Files include any fixes already applied on the backend.
            </p>
            <ul className="mt-5 space-y-3">
              {fileList.map((file) => (
                <li
                  key={String(file.id)}
                  className="glass-field flex items-center gap-3 rounded-[18px] px-4 py-3"
                >
                  <span className="min-w-0 flex-1 truncate text-[14px] text-foreground">
                    {file.filename}
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      download.mutate({ id: String(file.id), filename: file.filename })
                    }
                    disabled={download.isPending}
                    className="social-btn inline-flex shrink-0 items-center gap-2 rounded-full px-4 py-2 text-[12.5px] font-medium text-foreground disabled:opacity-45"
                  >
                    <Download className="size-[14px]" />
                    Download
                  </button>
                </li>
              ))}
            </ul>
          </section>
        )}
      </main>
    </DashboardShell>
  );
}
