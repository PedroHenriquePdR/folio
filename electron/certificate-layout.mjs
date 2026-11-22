export const stampSize = { width: 230, height: 82, minWidth: 130, minHeight: 54 };

function wrapName(name, size, width, measure) {
  const lines = [];
  let line = "";
  for (const word of name.split(/\s+/u)) {
    const candidate = line ? line + " " + word : word;
    if (measure(candidate, size) <= width) { line = candidate; continue; }
    if (line) lines.push(line);
    line = word;
    if (measure(word, size) <= width) continue;
    line = "";
    for (const char of word) {
      if (line && measure(line + char, size) > width) { lines.push(line); line = ""; }
      line += char;
    }
  }
  if (line) lines.push(line);
  return lines;
}

// Shared by the preview and the PDF appearance. Baselines are measured from the top.
export function stampLayout(lines, width, height, measure) {
  const scale = Math.min(width / stampSize.width, height / stampSize.height);
  const padding = 7 * scale, border = 0.9 * scale;
  const contentWidth = width - 2 * padding, availableHeight = height - 2 * padding;
  const leading = 1.23;
  const heightOf = rows => rows.reduce((sum, row) => sum + leading * row.size, 0);
  function rowsAt(factor) {
    const bodySize = 10 * factor, nameSize = 13 * factor;
    return lines.flatMap((text, index) => index === 1
      ? wrapName(text, nameSize, contentWidth, measure).map(text => ({ text, size: nameSize }))
      : [{ text, size: Math.min(bodySize, bodySize * contentWidth / measure(text, bodySize)) }]);
  }
  let rows = rowsAt(scale);
  if (heightOf(rows) > availableHeight) {
    // As the type gets smaller a long name can fit on fewer lines, leaving room for larger text.
    let low = scale * availableHeight / heightOf(rows), high = scale;
    rows = rowsAt(low);
    for (let i = 0; i < 8; i++) {
      const middle = (low + high) / 2;
      const candidate = rowsAt(middle);
      if (heightOf(candidate) <= availableHeight) { low = middle; rows = candidate; }
      else high = middle;
    }
  }
  let top = (height - heightOf(rows)) / 2;
  return { padding, border, rows: rows.map(({ text, size }) => {
    const baseline = top + 0.95 * size;
    top += leading * size;
    return { text, size, x: padding, baseline };
  }) };
}
