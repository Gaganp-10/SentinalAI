import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { FolderPlus, X } from "lucide-react";
import { GlassField } from "../auth/GlassField";
import { PrimaryButton } from "../auth/PrimaryButton";

export function NewProjectModal({
  open,
  onClose,
  onSubmit,
  loading,
  error,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (name: string) => void;
  loading: boolean;
  error?: string | undefined;
}) {
  const [name, setName] = useState("");
  const [localError, setLocalError] = useState<string | undefined>(undefined);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-5 backdrop-blur-md"
          onClick={onClose}
        >
          <motion.div
            initial={{ opacity: 0, y: 18, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.98 }}
            transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-label="Create a new project"
            className="glass-card w-full max-w-[420px] rounded-[32px] p-7"
          >
            <div className="flex items-center gap-3">
              <span className="icon-chip flex size-[38px] items-center justify-center rounded-full text-foreground">
                <FolderPlus className="size-[18px]" />
              </span>
              <h2 className="flex-1 text-[19px] font-semibold tracking-[-0.02em] text-foreground">
                New project
              </h2>
              <button
                type="button"
                aria-label="Close"
                onClick={onClose}
                className="flex size-8 items-center justify-center rounded-full text-muted-foreground hover:text-foreground"
              >
                <X className="size-[17px]" />
              </button>
            </div>

            <form
              className="mt-6 space-y-5"
              onSubmit={(e) => {
                e.preventDefault();
                if (name.trim().length < 1) {
                  setLocalError("Enter a project name");
                  return;
                }
                setLocalError(undefined);
                onSubmit(name.trim());
              }}
            >
              <GlassField
                label="Project name"
                placeholder="e.g. payments-service"
                icon={<FolderPlus className="size-[16px]" />}
                type="text"
                value={name}
                error={localError ?? error}
                onChange={(e) => setName(e.target.value)}
              />
              <PrimaryButton type="submit" loading={loading}>
                {loading ? "Creating" : "Create project"}
              </PrimaryButton>
            </form>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
