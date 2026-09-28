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

  const hasValue =
    (props.value !== undefined && props.value !== "") ||
    (props.defaultValue !== undefined && props.defaultValue !== "");
  const isFloating = focused || Boolean(hasValue);

  return (
    <div className="space-y-1.5">
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

        <div className="relative flex h-full flex-1 flex-col justify-center min-w-0">
          <input
            id={id}
            {...props}
            type={isPassword ? (reveal ? "text" : "password") : props.type}
            placeholder={props.placeholder || " "}
            onFocus={(e) => {
              setFocused(true);
              props.onFocus?.(e);
            }}
            onBlur={(e) => {
              setFocused(false);
              props.onBlur?.(e);
            }}
            className={cn(
              "peer w-full bg-transparent text-[14.5px] font-normal tracking-[-0.01em] text-foreground outline-none",
              "pt-3.5 pb-0.5",
              !focused && "placeholder:text-transparent",
              focused && "placeholder:text-muted-foreground/45",
            )}
          />

          <label
            htmlFor={id}
            className={cn(
              "floating-label pointer-events-none absolute left-0 select-none",
              "top-1/2 -translate-y-1/2 text-[14px] text-muted-foreground/75 font-normal",
              isFloating && "!top-[9px] !translate-y-0 !text-[11px] !font-medium text-muted-foreground",
              focused && "!text-foreground/90",
              "peer-focus:!top-[9px] peer-focus:!translate-y-0 peer-focus:!text-[11px] peer-focus:!font-medium peer-focus:!text-foreground/90",
              "peer-[:not(:placeholder-shown)]:!top-[9px] peer-[:not(:placeholder-shown)]:!translate-y-0 peer-[:not(:placeholder-shown)]:!text-[11px] peer-[:not(:placeholder-shown)]:!font-medium",
              "peer-autofill:!top-[9px] peer-autofill:!translate-y-0 peer-autofill:!text-[11px] peer-autofill:!font-medium",
              "peer-[-webkit-autofill]:!top-[9px] peer-[-webkit-autofill]:!translate-y-0 peer-[-webkit-autofill]:!text-[11px] peer-[-webkit-autofill]:!font-medium",
            )}
          >
            {label}
          </label>
        </div>

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
