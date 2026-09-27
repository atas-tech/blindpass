import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { Link, type LinkProps } from "react-router";
import { Icon, type IconName } from "./icon.js";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "quiet";
export type ButtonSize = "sm" | "md";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: IconName;
  iconEnd?: IconName;
  busy?: boolean;
  children?: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", icon, iconEnd, busy = false, className, children, disabled, type = "button", ...rest },
  ref
) {
  const classes = ["btn", `btn-${variant}`, `btn-${size}`, busy ? "is-busy" : "", !children ? "btn-icon-only" : "", className ?? ""]
    .filter(Boolean)
    .join(" ");
  return (
    <button ref={ref} type={type} className={classes} disabled={disabled || busy} aria-busy={busy || undefined} {...rest}>
      {busy ? <span className="spinner" aria-hidden="true" /> : icon ? <Icon name={icon} size={size === "sm" ? 15 : 17} /> : null}
      {children ? <span className="btn-label">{children}</span> : null}
      {iconEnd && !busy ? <Icon name={iconEnd} size={size === "sm" ? 15 : 17} className="btn-icon-end" /> : null}
    </button>
  );
});

interface ButtonLinkProps extends LinkProps {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: IconName;
  iconEnd?: IconName;
}

export function ButtonLink({ variant = "secondary", size = "md", icon, iconEnd, className, children, ...rest }: ButtonLinkProps) {
  const classes = ["btn", `btn-${variant}`, `btn-${size}`, className ?? ""].filter(Boolean).join(" ");
  return (
    <Link className={classes} {...rest}>
      {icon ? <Icon name={icon} size={size === "sm" ? 15 : 17} /> : null}
      <span className="btn-label">{children as ReactNode}</span>
      {iconEnd ? <Icon name={iconEnd} size={size === "sm" ? 15 : 17} className="btn-icon-end" /> : null}
    </Link>
  );
}
