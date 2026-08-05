import { motion } from "framer-motion";
import { FileCode2 } from "lucide-react";
import { formatBytes, type ProjectFile } from "../../api/files";

export function FileList({
  files,
  loading,
  error,
}: {
  files: ProjectFile[];
  loading: boolean;
  error?: string | undefined;
}) {
  return (
    <section className="glass-card mt-6 rounded-[32px] p-6 sm:p-7">
      <h2 className="text-[16px] font-semibold tracking-[-0.02em] text-foreground">
        Uploaded files
      </h2>

      {loading && (
        <div className="mt-5 space-y-3">
          {[0, 1].map((i) => (
            <div key={i} className="h-[58px] animate-pulse rounded-[18px] bg-foreground/[0.06]" />
          ))}
        </div>
      )}

      {error && !loading && (
        <p role="alert" className="mt-4 text-[13.5px] text-destructive">
          {error}
        </p>
      )}

      {!loading && !error && files.length === 0 && (
        <p className="mt-4 text-[13.5px] text-muted-foreground">
          No files uploaded yet — drop a file above to get started
        </p>
      )}

      {!loading && files.length > 0 && (
        <ul className="mt-5 space-y-3">
          {files.map((file, i) => (
            <motion.li
              key={String(file.id)}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: i * 0.04, ease: [0.16, 1, 0.3, 1] }}
              className="glass-field flex items-center gap-3 rounded-[18px] px-4 py-3"
            >
              <span className="icon-chip flex size-[34px] shrink-0 items-center justify-center rounded-full text-foreground">
                <FileCode2 className="size-[16px]" />
              </span>
              <span className="min-w-0 flex-1 truncate text-[14px] text-foreground">
                {file.filename}
              </span>
              {file.language && (
                <span className="icon-chip hidden rounded-full px-2.5 py-1 text-[11.5px] uppercase tracking-[0.06em] text-muted-foreground sm:inline">
                  {file.language}
                </span>
              )}
              <span className="shrink-0 text-[12.5px] text-muted-foreground">
                {formatBytes(file.size)}
              </span>
            </motion.li>
          ))}
        </ul>
      )}
    </section>
  );
}
