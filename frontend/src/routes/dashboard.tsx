import { useEffect, useMemo, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Plus, ShieldAlert } from "lucide-react";
import axios from "axios";
import { toast } from "sonner";
import { DashboardShell } from "../components/dashboard/DashboardShell";
import { TopNav } from "../components/dashboard/TopNav";
import { ProjectCard } from "../components/dashboard/ProjectCard";
import { NewProjectModal } from "../components/dashboard/NewProjectModal";
import { PrimaryButton } from "../components/auth/PrimaryButton";
import { getCurrentUser } from "../api/auth";
import { clearToken, toApiErrorMessage } from "../api/client";
import { createProject, latestScan, listProjects, listScans } from "../api/projects";

export const Route = createFileRoute("/dashboard")({
  head: () => ({
    meta: [
      { title: "Security Overview — SentinelAI" },
      {
        name: "description",
        content:
          "Review your SentinelAI projects, their latest vulnerability scans and open findings in one security overview.",
      },
      { property: "og:title", content: "Security Overview — SentinelAI" },
      {
        property: "og:description",
        content: "Your SentinelAI projects and the latest vulnerability scan results.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: DashboardPage,
});

function isUnauthorized(error: unknown) {
  return axios.isAxiosError(error) && error.response?.status === 401;
}

function DashboardPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [modalOpen, setModalOpen] = useState(false);

  const me = useQuery({ queryKey: ["auth", "me"], queryFn: getCurrentUser, retry: false });
  const projects = useQuery({ queryKey: ["projects"], queryFn: listProjects, retry: false });

  const scanQueries = useQueries({
    queries: (projects.data ?? []).map((p) => ({
      queryKey: ["projects", String(p.id), "scans"],
      queryFn: () => listScans(String(p.id)),
      retry: false,
    })),
  });

  const authError = isUnauthorized(projects.error) || isUnauthorized(me.error);

  useEffect(() => {
    if (authError) {
      clearToken();
      toast.error("Your session expired. Please log in again.");
      navigate({ to: "/" });
    }
  }, [authError, navigate]);

  const openFindings = useMemo(
    () =>
      scanQueries.reduce((sum, q) => sum + (latestScan(q.data)?.total_issues ?? 0), 0),
    [scanQueries],
  );

  const create = useMutation({
    mutationFn: (name: string) => createProject(name),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      setModalOpen(false);
      toast.success("Project created");
    },
    onError: (error) => toast.error(toApiErrorMessage(error)),
  });

  const list = projects.data ?? [];

  return (
    <DashboardShell>
      <TopNav email={me.data?.email ?? me.data?.username} />

      <main className="mx-auto w-full max-w-[1100px] px-5 pb-20 pt-10 sm:px-8">
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          className="flex flex-wrap items-end justify-between gap-5"
        >
          <div>
            <h1 className="text-[32px] font-semibold leading-[1.15] tracking-[-0.03em] text-foreground">
              Security Overview
            </h1>
            <p className="mt-2 text-[14px] text-muted-foreground">
              {projects.isLoading
                ? "Loading your projects…"
                : `${list.length} ${list.length === 1 ? "project" : "projects"} · ${openFindings} open ${
                    openFindings === 1 ? "finding" : "findings"
                  }`}
            </p>
          </div>

          <div className="w-full sm:w-[210px]">
            <PrimaryButton type="button" onClick={() => setModalOpen(true)}>
              <Plus className="size-[18px]" />
              New Project
            </PrimaryButton>
          </div>
        </motion.div>

        <div className="mt-9">
          {projects.isLoading && (
            <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
              {[0, 1, 2].map((i) => (
                <div key={i} className="glass-card h-[168px] animate-pulse rounded-[26px]" />
              ))}
            </div>
          )}

          {projects.isError && !authError && (
            <div className="glass-card flex items-start gap-3 rounded-[26px] p-6">
              <ShieldAlert className="mt-0.5 size-[19px] shrink-0 text-destructive" />
              <div>
                <p className="text-[15px] font-medium text-foreground">
                  Could not load your projects
                </p>
                <p className="mt-1 text-[13.5px] text-destructive">
                  {toApiErrorMessage(projects.error)}
                </p>
                <button
                  type="button"
                  onClick={() => projects.refetch()}
                  className="social-btn mt-4 rounded-full px-4 py-2 text-[13px] font-medium text-foreground"
                >
                  Try again
                </button>
              </div>
            </div>
          )}

          {projects.isSuccess && list.length === 0 && (
            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.55 }}
              className="glass-card flex flex-col items-center rounded-[32px] px-7 py-14 text-center"
            >
              <span className="icon-chip flex size-[52px] items-center justify-center rounded-full text-foreground">
                <ShieldAlert className="size-[22px]" />
              </span>
              <h2 className="mt-5 text-[20px] font-semibold tracking-[-0.02em] text-foreground">
                No projects yet
              </h2>
              <p className="mt-2 max-w-[340px] text-[14px] text-muted-foreground">
                Create your first one to start scanning your codebase for vulnerabilities.
              </p>
              <div className="mt-7 w-full max-w-[240px]">
                <PrimaryButton type="button" onClick={() => setModalOpen(true)}>
                  <Plus className="size-[18px]" />
                  New Project
                </PrimaryButton>
              </div>
            </motion.div>
          )}

          {list.length > 0 && (
            <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
              {list.map((project, i) => (
                <ProjectCard
                  key={String(project.id)}
                  project={project}
                  index={i}
                  scans={scanQueries[i]?.data}
                  scansLoading={scanQueries[i]?.isLoading ?? false}
                />
              ))}
            </div>
          )}
        </div>
      </main>

      <NewProjectModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        loading={create.isPending}
        error={create.isError ? toApiErrorMessage(create.error) : undefined}
        onSubmit={(name) => create.mutate(name)}
      />
    </DashboardShell>
  );
}
