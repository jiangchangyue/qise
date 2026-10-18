import type { CSSProperties } from "react";
export type IconName = "home" | "shield" | "scan" | "events" | "rules" | "model" | "tools" | "settings" | "arrow" | "chevron" | "check" | "activity" | "backup" | "code" | "flask" | "close" | "refresh" | "globe" | "lock" | "help";
const paths: Record<IconName, string[]> = {
  home: ["M3 10 12 3l9 7", "M5 9v11h5v-6h4v6h5V9"],
  shield: ["M12 3 4.5 6v5c0 5 3.5 8 7.5 10 4-2 7.5-5 7.5-10V6L12 3Z", "m8.5 12 2.5 2.5 4.5-5"],
  scan: ["M8 3H4a1 1 0 0 0-1 1v4m13-5h4a1 1 0 0 1 1 1v4M3 16v4a1 1 0 0 0 1 1h4m8 0h4a1 1 0 0 0 1-1v-4", "M7 12h10", "M9 8h6m-6 8h6"],
  events: ["M8 3H5a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V4a1 1 0 0 0-1-1h-3", "M8 2h8v4H8z", "M8 11h8m-8 4h5"],
  rules: ["M4 6h16M4 12h16M4 18h16", "M8 4v4m8 2v4m-6 2v4"],
  model: ["M7 7h10v10H7z", "M9 3v4m6-4v4m-6 10v4m6-4v4M3 9h4m-4 6h4m10-6h4m-4 6h4", "M10 10h4v4h-4z"],
  tools: ["M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"],
  settings: ["m9.5 3-.8 2-2 .9-2-.4-2.2 3.8 1.4 1.6v2.2L2.5 15l2.2 3.8 2-.4 2 .9.8 2h4.4l.8-2 2-.9 2 .4 2.2-3.8-1.4-1.6v-2.2l1.4-1.6-2.2-3.8-2 .4-2-.9-.8-2Z", "M15.5 12a3.5 3.5 0 1 1-7 0 3.5 3.5 0 0 1 7 0Z"],
  arrow: ["M5 12h14m-5-5 5 5-5 5"], chevron: ["m9 5 7 7-7 7"], check: ["m5 12 4 4L19 6"],
  activity: ["M3 12h4l3-8 4 16 3-8h4"],
  backup: ["M4 8v5h5", "M4.2 12a8 8 0 1 1 2 5.3", "M12 8v4l3 2"],
  code: ["m8 6-6 6 6 6m8-12 6 6-6 6M14 3l-4 18"],
  flask: ["M9 3h6m-5 0v6L4.5 18a2 2 0 0 0 1.7 3h11.6a2 2 0 0 0 1.7-3L14 9V3", "M8 15h8"],
  close: ["m6 6 12 12M6 18 18 6"], refresh: ["M20 7v5h-5", "M4 17v-5h5", "M5.1 8a8 8 0 0 1 13.2-2L20 8M4 16l1.7 2A8 8 0 0 0 19 16"],
  globe: ["M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM3 12h18", "M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z"],
  lock: ["M5 10h14v11H5z", "M8 10V6a4 4 0 0 1 8 0v4m-4 5v2"],
  help: ["M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z", "M9 9a3 3 0 1 1 4.5 2.6c-1 .6-1.5 1.2-1.5 2.4m0 3v.01"],
};
export default function Icon({ name, size = 18, className = "", style }: { name: IconName; size?: number; className?: string; style?: CSSProperties }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className={className} style={style}>{paths[name].map((d, i) => <path key={i} d={d} />)}</svg>;
}
