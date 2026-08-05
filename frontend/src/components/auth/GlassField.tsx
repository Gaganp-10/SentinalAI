import { useId, useState, type ComponentPropsWithoutRef, type ReactNode } from "react";
import { motion } from "framer-motion";
import { Eye, EyeOff } from "lucide-react";
import { cn } from "../../lib/utils";

type GlassFieldProps = {
  label: string;
  icon: ReactNode;
  error?: string | undefined;
  isPassword?: boolean | undefined;
} & Omit<ComponentPropsWithoutRef<"input">, "className">;

export function GlassField({ label, icon, error, isPassword, ...props }: GlassFieldProps) {
  const id = useId();
  const [focused, setFocused] = useState(false);
  const [reveal, setReveal] = useState(false);

  return (
    <div className="space-y-2">
      <label
        htmlFor={id}
        className="block pl-1 text-[13.5px] font-normal tracking-[-0.01em] text-muted-foreground"
      >
        {label}
      </label>

      <motion.div
        animate={{ scale: focused ? 1.01 : 1 }}
        transition={{ type: "spring", stiffness: 420, damping: 30 }}
        className={cn(
          "glass-field relative flex h-[58px] items-center rounded-full px-4",
          focused && "glass-field-focus",
          error && "glass-field-error",
        )}
      >
        <span
          className={cn(
            "icon-chip pointer-events-none mr-3 flex size-[30px] shrink-0 items-center justify-center rounded-full text-muted-foreground transition-colors duration-300",
            focused && "text-foreground",
          )}
        >
          {icon}
        </span>

        <input
          id={id}
          {...props}
          type={isPassword ? (reveal ? "text" : "password") : props.type}
          onFocus={(e) => {
            setFocused(true);
            props.onFocus?.(e);
          }}
          onBlur={(e) => {
            setFocused(false);
            props.onBlur?.(e);
          }}
          className="min-w-0 flex-1 bg-transparent text-[15px] font-normal tracking-[-0.01em] text-foreground outline-none placeholder:text-muted-foreground/80"
        />

        {isPassword && (
          <button
            type="button"
            aria-label={reveal ? "Hide password" : "Show password"}
            onClick={() => setReveal((v) => !v)}
            className="ml-2 flex size-9 shrink-0 items-center justify-center rounded-full text-muted-foreground transition-colors duration-200 hover:text-foreground"
          >
            {reveal ? <EyeOff className="size-[18px]" /> : <Eye className="size-[18px]" />}
          </button>
        )}
      </motion.div>

      {error && (
        <motion.p
          initial={{ opacity: 0, y: -4 }}
          animate={{ opacity: 1, y: 0 }}
          className="pl-4 text-[12.5px] font-medium text-destructive"
        >
          {error}
        </motion.p>
      )}
    </div>
  );
}
