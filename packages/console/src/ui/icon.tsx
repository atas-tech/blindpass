import { createElement } from "react";
import { ICONS } from "../../../../assets/ui/icons.js";

export type IconName = keyof typeof ICONS & string;

interface IconProps {
  name: IconName;
  size?: number;
  className?: string;
  /** Icons are decorative unless a label is given. */
  label?: string;
}

export function Icon({ name, size = 18, className, label }: IconProps) {
  const parts = ICONS[name] ?? [];
  return (
    <svg
      className={className ? `icon ${className}` : "icon"}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden={label ? undefined : true}
      role={label ? "img" : undefined}
      aria-label={label}
      focusable="false"
    >
      {parts.map(([tag, attributes], index) => createElement(tag, { key: index, ...attributes }))}
    </svg>
  );
}
