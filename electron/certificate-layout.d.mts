export const stampSize: { width: number; height: number; minWidth: number; minHeight: number };
export function stampLayout(lines: string[], width: number, height: number, measure: (text: string, size: number) => number): {
  padding: number;
  border: number;
  rows: { text: string; size: number; x: number; baseline: number }[];
};
