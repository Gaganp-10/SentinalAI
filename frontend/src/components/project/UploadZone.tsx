import { useRef, useState } from "react";
import { motion } from "framer-motion";
import { FileUp, Loader2 } from "lucide-react";
import { ACCEPTED_EXTENSIONS } from "../../api/files";

export function UploadZone({
  onFile,
  uploading,
  progress,
  error,
}: {
  onFile: (file: File) => void;
  uploading: boolean;
  progress: number;
  error?: string | undefined;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  return (
    <motion.section
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.55, ease: [0.16, 1, 0.3, 1] }}
      className="glass-card rounded-[32px] p-6 sm:p-7"
    >
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const file = e.dataTransfer.files?.[0];
          if (file) onFile(file);
        }}
        className={`flex flex-col items-center rounded-[24px] border border-dashed px-6 py-11 text-center transition-colors duration-300 ${
          dragging
            ? "border-foreground/50 bg-foreground/[0.07]"
            : "border-border bg-foreground/[0.02]"
        }`}
      >
        <span className="icon-chip flex size-[52px] items-center justify-center rounded-full text-foreground">
          {uploading ? (
            <Loader2 className="size-[22px] animate-spin" />
          ) : (
            <FileUp className="size-[21px]" />
          )}
        </span>

        <h2 className="mt-5 text-[18px] font-semibold tracking-[-0.02em] text-foreground">
          {uploading ? "Uploading…" : "Drop a source file to scan"}
        </h2>
        <p className="mt-2 max-w-[380px] text-[13.5px] text-muted-foreground">
          {ACCEPTED_EXTENSIONS.join(" · ")}
        </p>

        <input
          ref={inputRef}
          type="file"
          className="hidden"
          accept={ACCEPTED_EXTENSIONS.join(",")}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) onFile(file);
            e.target.value = "";
          }}
        />

        <button
          type="button"
          disabled={uploading}
          onClick={() => inputRef.current?.click()}
          className="social-btn mt-6 rounded-full px-6 py-2.5 text-[13.5px] font-medium text-foreground disabled:opacity-50"
        >
          Select File
        </button>

        {uploading && (
          <div className="mt-6 w-full max-w-[320px]">
            <div className="h-[6px] w-full overflow-hidden rounded-full bg-foreground/10">
              <div
                className="h-full rounded-full bg-foreground/70 transition-[width] duration-150"
                style={{ width: `${progress}%` }}
              />
            </div>
            <p className="mt-2 text-[12.5px] text-muted-foreground">{progress}% uploaded</p>
          </div>
        )}

        {error && !uploading && (
          <p role="alert" className="mt-5 max-w-[420px] text-[13px] text-destructive">
            {error}
          </p>
        )}
      </div>
    </motion.section>
  );
}
