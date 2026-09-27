export type IconPart = ["path" | "circle" | "rect" | "line" | "polyline", Record<string, string | number>];
export declare const ICONS: Record<string, IconPart[]>;
export declare function hasIcon(name: string): boolean;
