const { existsSync, readFileSync } = require("node:fs");
const path = require("node:path");

function inherited(dict, key, resolve) {
  const visited = new Set();
  while (dict && !visited.has(dict)) {
    visited.add(dict);
    const value = dict.get(key, resolve);
    if (value && value.type !== "null") return value;
    dict = dict.getDict("Parent", resolve);
  }
}

function readBox(array, resolve) {
  if (array?.type !== "array" || array.length !== 4) return;
  const [x0, y0, x1, y1] = [0, 1, 2, 3].map(i => array.at(i, resolve)?.value);
  if (![x0, y0, x1, y1].every(Number.isFinite) || x0 === x1 || y0 === y1) return;
  return [Math.min(x0, x1), Math.min(y0, y1), Math.max(x0, x1), Math.max(y0, y1)];
}

function widgetGeometry(page, rect, resolve, minWidth, minHeight) {
  if (!Array.isArray(rect) || rect.length !== 4 || !Array.from(rect).every(Number.isFinite)) return;
  // Match the viewer's page.view, including inherited boxes, offsets and PDF's default MediaBox.
  const media = readBox(inherited(page.dict, "MediaBox", resolve), resolve) ?? [0, 0, 612, 792];
  const crop = readBox(inherited(page.dict, "CropBox", resolve), resolve) ?? media;
  const intersection = [Math.max(media[0], crop[0]), Math.max(media[1], crop[1]),
    Math.min(media[2], crop[2]), Math.min(media[3], crop[3])];
  const box = intersection[0] < intersection[2] && intersection[1] < intersection[3] ? intersection : media;
  // A viewport round-trip can put an edge a few floating-point units past the actual boundary.
  const tolerance = 16 * Number.EPSILON * Math.max(1, ...box.map(Math.abs));
  const snapped = rect.map((value, i) => Math.abs(value - box[i]) <= tolerance ? box[i] : value);
  const [x0, y0, x1, y1] = snapped;
  if (x0 < box[0] || y0 < box[1] || x1 > box[2] || y1 > box[3]) return;
  const angle = inherited(page.dict, "Rotate", resolve)?.value;
  const rotate = Number.isInteger(angle) && angle % 90 === 0 ? (angle % 360 + 360) % 360 : 0;
  const unit = page.dict.getNumber("UserUnit", resolve)?.value;
  const userUnit = Number.isFinite(unit) && unit > 0 ? unit : 1;
  const rawWidth = x1 - x0, rawHeight = y1 - y0;
  const sideways = rotate === 90 || rotate === 270;
  const width = sideways ? rawHeight : rawWidth;
  const height = sideways ? rawWidth : rawHeight;
  if (!Number.isFinite(width * userUnit) || !Number.isFinite(height * userUnit)
    || width * userUnit + 1e-7 < minWidth || height * userUnit + 1e-7 < minHeight) return;
  // PDF displays /Rotate clockwise. Paint the upright design counterclockwise in the page's own coordinates.
  const matrix = {
    0: [1, 0, 0, 1, 0, 0], 90: [0, 1, -1, 0, rawWidth, 0],
    180: [-1, 0, 0, -1, rawWidth, rawHeight], 270: [0, -1, 1, 0, 0, rawHeight],
  }[rotate];
  return { rect: snapped, width, height, rawWidth, rawHeight, matrix };
}

function loadStampFont(pdf, fail) {
  const bundled = path.join(__dirname, "..", "dist", "pdfjs", "DejaVuSans.ttf");
  try {
    return pdf.embedFont(readFileSync(existsSync(bundled) ? bundled : require.resolve("dejavu-fonts-ttf/ttf/DejaVuSans.ttf")));
  } catch { fail("pdf_signature_failed"); }
}

async function prepareAppearance(pdf, pages, appearance, fail) {
  const { stampSize, stampLayout } = await import("./certificate-layout.mjs");
  const number = appearance?.placement?.pageNumber;
  const page = Number.isSafeInteger(number) && pages[number - 1];
  const rect = appearance?.placement?.rect;
  const geometry = page && widgetGeometry(page, rect, ref => pdf.getObject(ref), stampSize.minWidth, stampSize.minHeight);
  if (!geometry) fail("invalid_placement");
  const { width, height, rawWidth, rawHeight, matrix } = geometry;
  const { PdfDict, PdfString, ops } = await import("@libpdf/core");
  const { stampLines } = await import("./certificate-stamp.mjs");
  const lines = stampLines(appearance.holder, appearance.taxId, appearance.signedAt, appearance.utcOffsetMinutes);
  const font = loadStampFont(pdf, fail);
  if (!font.canEncode(lines.join(""))) fail("stamp_glyph");
  const { border, rows } = stampLayout(lines, width, height, (text, size) => font.widthOfTextAtSize(text, size));
  const operators = [
    ops.pushGraphicsState(), ops.concatMatrix(...matrix),
    ops.setNonStrokingGray(1), ops.setStrokingRGB(83 / 255, 101 / 255, 111 / 255), ops.setLineWidth(border),
    ops.rectangle(border / 2, border / 2, width - border, height - border), ops.fillAndStroke(),
    ops.setNonStrokingRGB(23 / 255, 42 / 255, 52 / 255), ops.beginText(),
  ];
  for (const { text, size, x, baseline } of rows) {
    // The embedded Identity-H font uses two-byte, big-endian glyph IDs.
    const glyphs = font.encodeTextToGids(text);
    const bytes = Buffer.alloc(glyphs.length * 2);
    glyphs.forEach((id, i) => bytes.writeUInt16BE(id, 2 * i));
    operators.push(ops.setFont("StampFont", size), ops.setTextMatrix(1, 0, 0, 1, x, height - baseline),
      ops.showText(PdfString.fromBytes(bytes)));
  }
  operators.push(ops.endText(), ops.popGraphicsState());
  const normal = pdf.createFormXObject({ bbox: { x: 0, y: 0, width: rawWidth, height: rawHeight }, operators });
  pdf.getObject(normal.ref).set("Resources", PdfDict.of({ Font: PdfDict.of({ StampFont: font.ref }) }));
  return { page, rect: geometry.rect, normal: normal.ref };
}

module.exports = { prepareAppearance };
