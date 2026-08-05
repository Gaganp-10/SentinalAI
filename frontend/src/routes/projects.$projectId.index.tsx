import { useEffect, useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { ArrowLeft } from "lucide-react";
import axios from "axios";
import { toast } from "sonner";
import { DashboardShell } from "../components/dashboard/DashboardShell";
import { TopNav } from "../components/dashboard/TopNav";
import { UploadZone } from "../components/project/UploadZone";
import { FileList } from "../components/project/FileList";
import { ScanPanel } from "../components/project/ScanPanel";
import { ScanHistoryList } from "../components/project/ScanHistoryList";
import { getCurrentUser } from "../api/auth";
import { clearToken, toApiErrorMessage } from "../api/client";
import { getProject, listScans, type ScanHistory } from "../api/projects";
import { getScan, listFiles, startScan, uploadFile } from "../api/files";

export const Route = createFileRoute("/projects/$projectId/")({
  head: () => ({
    meta: [
      { title: "Upload & Scan — SentinelAI" },
      {
        name: "description",
        content:
          "Upload source files and run a real SentinelAI vulnerability scan, then review scan history for this project.",
      },
      { property: "og:title", content: "Upload & Scan — SentinelAI" },
      {
        property: "og:description",
        content: "Upload code and trigger vulnerability scans for a SentinelAI project.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ProjectDetailPage,
});

function isUnauthorized(error: unknown) {
  return axios.isAxiosError(error) && error.response?.status === 401;
}

function ProjectDetailPage() {
  const { projectId } = Route.useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [progress, setProgress] = useState(0);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [finishedScan, setFinishedScan] = useState<ScanHistory | undefined>(undefined);

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
  const scans = useQuery({
    queryKey: ["projects", projectId, "scans"],
    queryFn: () => listScans(projectId),
    retry: false,
  });

  // Real polling of GET /scans/{id} while the backend reports pending/running.
  const polled = useQuery({
    queryKey: ["scans", activeScanId],
    queryFn: () => getScan(activeScanId as string),
    enabled: Boolean(activeScanId),
    retry: false,
    refetchInterval: (query) => {
      const status = query.state.data?.status?.toLowerCase();
      return status === "pending" || status === "running" ? 2000 : false;
    },
  });

  const authError =
    isUnauthorized(project.error) || isUnauthorized(files.error) || isUnauthorized(me.error);

  useEffect(() => {
    if (authError) {
      clearToken();
      toast.error("Your session expired. Please log in again.");
      navigate({ to: "/" });
    }
  }, [authError, navigate]);

  // Resume tracking after a refresh if the backend still reports a scan in progress.
  const inFlightFromHistory = (scans.data ?? []).find((s) => {
    const status = s.status?.toLowerCase();
    return status === "pending" || status === "running";
  });
  useEffect(() => {
    if (!activeScanId && !finishedScan && inFlightFromHistory) {
      setActiveScanId(String(inFlightFromHistory.id));
    }
  }, [activeScanId, finishedScan, inFlightFromHistory]);



  const polledStatus = polled.data?.status?.toLowerCase();
  useEffect(() => {
    if (!polled.data) return;
    if (polledStatus === "completed" || polledStatus === "failed") {
      setFinishedScan(polled.data);
      setActiveScanId(null);
      void queryClient.invalidateQueries({ queryKey: ["projects", projectId, "scans"] });
      void queryClient.invalidateQueries({ queryKey: ["projects"] });
      if (polledStatus === "completed") {
        toast.success(`Scan complete — ${polled.data.total_issues} issues found`);
      } else {
        toast.error("Scan failed on the backend");
      }
    }
  }, [polled.data, polledStatus, projectId, queryClient]);

  const upload = useMutation({
    mutationFn: (file: File) => uploadFile(projectId, file, setProgress),
    onMutate: () => setProgress(0),
    onSuccess: async (file) => {
      await queryClient.invalidateQueries({ queryKey: ["projects", projectId, "files"] });
      toast.success(`Uploaded ${file.filename}`);
    },
    onError: (error) => toast.error(toApiErrorMessage(error)),
  });

  const scan = useMutation({
    mutationFn: () => startScan(projectId),
    onSuccess: (created) => {
      setFinishedScan(undefined);
      setActiveScanId(String(created.id));
      void queryClient.invalidateQueries({ queryKey: ["projects", projectId, "scans"] });
    },
    onError: (error) => toast.error(toApiErrorMessage(error)),
  });

  const fileList = files.data ?? [];
  const currentScan = activeScanId ? polled.data ?? scan.data : finishedScan;

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
            to="/dashboard"
            className="inline-flex items-center gap-1.5 text-[13px] text-muted-foreground transition-colors hover:text-foreground"
          >
            <ArrowLeft className="size-[14px]" />
            Dashboard
          </Link>

          <h1 className="mt-3 text-[30px] font-semibold leading-[1.15] tracking-[-0.03em] text-foreground">
            {project.data?.project_name ?? (project.isLoading ? "Loading…" : "Project")}
          </h1>
          {project.isError && !authError && (
            <p role="alert" className="mt-2 text-[13.5px] text-destructive">
              {toApiErrorMessage(project.error)}
            </p>
          )}
        </motion.div>

        <div className="mt-7">
          <UploadZone
            onFile={(file) => upload.mutate(file)}
            uploading={upload.isPending}
            progress={progress}
            error={upload.isError ? toApiErrorMessage(upload.error) : undefined}
          />

          <FileList
            files={fileList}
            loading={files.isLoading}
            error={
              files.isError && !authError ? toApiErrorMessage(files.error) : undefined
            }
          />

          <ScanPanel
            projectId={projectId}
            hasFiles={fileList.length > 0}
            scan={currentScan}
            starting={scan.isPending}
            error={
              scan.isError
                ? toApiErrorMessage(scan.error)
                : polled.isError
                  ? toApiErrorMessage(polled.error)
                  : undefined
            }
            onScan={() => scan.mutate()}
          />

          <ScanHistoryList
            scans={scans.data ?? []}
            loading={scans.isLoading}
            error={scans.isError ? toApiErrorMessage(scans.error) : undefined}
          />
        </div>
      </main>
    </DashboardShell>
  );
}
