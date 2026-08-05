import type { ReactNode } from "react";
import { motion, type HTMLMotionProps } from "framer-motion";
import { Loader2 } from "lucide-react";
import { cn } from "../../lib/utils";

type PrimaryButtonProps = {
  children: ReactNode;
  loading?: boolean | undefined;
} & Omit<HTMLMotionProps<"button">, "className" | "children">;

export function PrimaryButton({ children, loading, disabled, ...props }: PrimaryButtonProps) {
  return (
    <motion.button
      {...props}
      disabled={disabled || loading}
      whileHover={{ y: -2 }}
      whileTap={{ scale: 0.975, y: 0 }}
      transition={{ type: "spring", stiffness: 500, damping: 28 }}
      className={cn(
        "btn-pill relative flex h-[60px] w-full items-center justify-center gap-2 rounded-full text-[16px] font-medium tracking-[-0.01em]",
        (disabled || loading) && "pointer-events-none opacity-70",
      )}
    >
      {loading && <Loader2 className="size-[18px] animate-spin" />}
      {children}
    </motion.button>
  );
}
