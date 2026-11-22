import { useEffect, useMemo, useRef, useState } from "react";
import type { PageViewport, RenderTask } from "pdfjs-dist";
import type { PDFDocumentProxy } from "./pdf";
import { stampLines } from "../electron/certificate-stamp.mjs";
import { stampLayout, stampSize } from "../electron/certificate-layout.mjs";

const { width: defaultWidth, height: defaultHeight, minWidth, minHeight } = stampSize;
const heightFor = (width: number) => Math.max(minHeight, width * defaultHeight / defaultWidth);

function useStampGraphic(lines: string[], width: number, height: number) {
  const [fontLoaded, setFontLoaded] = useState(false);
  useEffect(() => {
    let active = true;
    void document.fonts?.load("12px FolioArabic").then(() => { if (active) setFontLoaded(true); }).catch(() => {});
    return () => { active = false; };
  }, []);
  const measure = useMemo(() => {
    const ctx = document.createElement("canvas").getContext("2d")!;
    ctx.font = "1000px FolioArabic, sans-serif";
    ctx.fontKerning = "none";
    const advances = new Map<string, number>();
    // PDF font widths are rounded to thousandths of an em, glyph by glyph.
    return (text: string, size: number) => {
      let width = 0;
      for (const char of text) {
        let advance = advances.get(char);
        if (advance === undefined) {
          advance = Math.round(ctx.measureText(char).width);
          advances.set(char, advance);
        }
        width += advance;
      }
      return width * size / 1000;
    };
  }, [fontLoaded]);
  const { border, rows } = useMemo(() => stampLayout(lines, width, height, measure), [lines, width, height, measure]);
  return <svg viewBox={"0 0 " + width + " " + height} role="img" aria-label={lines.join(". ")}>
    <rect x={border / 2} y={border / 2} width={width - border} height={height - border}
      fill="white" stroke="#53656f" strokeWidth={border} />
    {rows.map((row, index) => <text key={index} x={row.x} y={row.baseline} fontSize={row.size}
      fontFamily="FolioArabic, sans-serif" fill="#172a34">{row.text}</text>)}
  </svg>;
}

interface Props {
  pdf: PDFDocumentProxy;
  pageInput: string;
  certificate: SigningCertificate;
  placement?: CertificatePlacement;
  disabled: boolean;
  onPage(value: string): void;
  onPlace(placement: CertificatePlacement): void;
}

// The viewport uses physical points in the page's reading orientation. Only the final
// rectangle crosses the bridge, in the PDF's unrotated coordinates including the CropBox offset.
export function CertificateStampPlacement({ pdf, pageInput, certificate, placement, disabled, onPage, onPlace }: Props) {
  const pageNumber = Number(pageInput);
  const validPage = Number.isInteger(pageNumber) && pageNumber >= 1 && pageNumber <= pdf.numPages;
  const canvas = useRef<HTMLCanvasElement>(null);
  const [viewport, setViewport] = useState<PageViewport>();
  const [failed, setFailed] = useState(false);
  const [requestedWidth, setWidth] = useState(defaultWidth);
  const [time] = useState(() => new Date());
  const lines = useMemo(() => stampLines(certificate.stampName, certificate.taxId, time.toISOString(), -time.getTimezoneOffset()),
    [certificate, time]);
  useEffect(() => {
    if (!validPage) return;
    let active = true;
    let task: RenderTask | undefined;
    void (async () => {
      const page = await pdf.getPage(pageNumber);
      if (!active || !canvas.current) return;
      const native = page.getViewport({ scale: 1 });
      const raster = native.clone({ scale: Math.min(800 / native.width, 880 / native.height) });
      canvas.current.width = Math.ceil(raster.width);
      canvas.current.height = Math.ceil(raster.height);
      task = page.render({ canvas: canvas.current, viewport: raster });
      await task.promise;
      if (active) setViewport(native);
    })().catch(() => { if (active) setFailed(true); });
    return () => { active = false; task?.cancel(); };
  }, [pdf, pageNumber, validPage]);

  const tooSmall = !!viewport && (viewport.width < minWidth || viewport.height < minHeight);
  const maxWidth = viewport ? Math.max(minWidth, Math.floor(Math.min(350, viewport.width,
    viewport.height * defaultWidth / defaultHeight))) : 350;
  const width = Math.min(requestedWidth, maxWidth), height = heightFor(width);
  const corners = viewport && placement?.pageNumber === pageNumber ? [
    ...viewport.convertToViewportPoint(placement.rect[0], placement.rect[1]),
    ...viewport.convertToViewportPoint(placement.rect[2], placement.rect[3]),
  ] : undefined;
  const centerX = corners ? (corners[0] + corners[2]) / 2 : (viewport?.width ?? 0) / 2;
  const centerY = corners ? (corners[1] + corners[3]) / 2 : (viewport?.height ?? 0) / 2;

  function place(x: number, y: number, w = width) {
    if (!viewport || disabled || tooSmall) return;
    const h = heightFor(w);
    const left = Math.max(0, Math.min(viewport.width - w, x - w / 2));
    const top = Math.max(0, Math.min(viewport.height - h, y - h / 2));
    const [x1, y1] = viewport.convertToPdfPoint(left, top);
    const [x2, y2] = viewport.convertToPdfPoint(left + w, top + h);
    const [xmin, ymin, xmax, ymax] = viewport.viewBox;
    onPlace({ pageNumber, rect: [Math.max(xmin, Math.min(x1, x2)), Math.max(ymin, Math.min(y1, y2)),
      Math.min(xmax, Math.max(x1, x2)), Math.min(ymax, Math.max(y1, y2))] });
  }

  const stamp = useStampGraphic(lines, width, height);
  return <>
    <div className="certificate-sample">
      <h3>Stamp preview</h3>
      {stamp}
      <p>The time is set when you sign.</p>
    </div>
    <section className="signature-document certificate-page" aria-label="Stamp placement">
      <label className="certificate-page-number">Page
        <input type="number" aria-label="Stamp page" min={1} max={pdf.numPages} required value={pageInput}
          disabled={disabled} onChange={event => {
            const next = event.target.value;
            if (Number(next) !== pageNumber) { setViewport(undefined); setFailed(false); }
            onPage(next);
          }} /> of {pdf.numPages}
      </label>
      <label className="signature-range">Stamp width
        <input type="range" aria-label="Stamp width" aria-valuetext={width + " points"} min={minWidth} max={maxWidth}
          value={width} disabled={disabled || !viewport || tooSmall || maxWidth === minWidth} onChange={e => {
            const value = Number(e.target.value);
            setWidth(value);
            if (corners) place(centerX, centerY, value);
          }} />
      </label>
      <div className="signature-page-stage">
        {!viewport && <p role={failed ? "alert" : "status"}>{!validPage ? "Enter a page from 1 to " + pdf.numPages + "." :
          failed ? "Couldn’t preview this page." : "Loading page preview…"}</p>}
        <button type="button" className="signature-page certificate-paper" aria-label={"Place stamp on page " + pageNumber}
          aria-describedby="certificate-placement-hint" disabled={disabled || !viewport || tooSmall} hidden={!viewport}
          data-placeable={!!viewport && !disabled && !tooSmall || undefined}
          style={viewport ? { width: Math.min(400, 440 * viewport.width / viewport.height),
            aspectRatio: viewport.width / viewport.height } : undefined}
          onClick={event => {
            if (!viewport) return;
            if (!event.detail) { place(centerX, centerY); return; }
            const bounds = event.currentTarget.getBoundingClientRect();
            if (bounds.width && bounds.height) place((event.clientX - bounds.left) * viewport.width / bounds.width,
              (event.clientY - bounds.top) * viewport.height / bounds.height);
          }} onKeyDown={event => {
            if (event.altKey || !["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) return;
            event.preventDefault(); event.stopPropagation();
            place(centerX + (event.key === "ArrowLeft" ? -5 : event.key === "ArrowRight" ? 5 : 0),
              centerY + (event.key === "ArrowUp" ? -5 : event.key === "ArrowDown" ? 5 : 0));
          }}>
          <canvas ref={canvas} key={pageNumber} className="signature-page-background" aria-hidden="true" />
          {viewport && corners && <span className="signature-placement certificate-overlay" aria-hidden="true" style={{
            left: Math.min(corners[0], corners[2]) / viewport.width * 100 + "%",
            top: Math.min(corners[1], corners[3]) / viewport.height * 100 + "%",
            width: Math.abs(corners[2] - corners[0]) / viewport.width * 100 + "%",
            height: Math.abs(corners[3] - corners[1]) / viewport.height * 100 + "%",
          }}>{stamp}</span>}
        </button>
      </div>
      <p id="certificate-placement-hint" className="signature-hint" aria-live="polite">
        {tooSmall ? "This page is too small for a stamp. Choose another page or turn off the visible stamp." :
          failed ? "Choose another page or turn off the visible stamp." :
          corners ? "Click to reposition, or use the arrow keys to fine-tune." :
          "Click the page to place the stamp, or focus the page and press Enter."}
      </p>
    </section>
  </>;
}
