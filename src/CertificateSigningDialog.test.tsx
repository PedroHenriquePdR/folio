// @vitest-environment jsdom
import { act, type ComponentProps } from "react";
import { createRoot } from "react-dom/client";
import { afterAll, afterEach, beforeAll, beforeEach, expect, test, vi } from "vitest";
import { degrees, PDFDocument, PDFName, PDFNumber, PDFString } from "pdf-lib";
import { getDocument, type PDFDocumentProxy, type RenderTask } from "pdfjs-dist/legacy/build/pdf.mjs";
import { CertificateSigningDialog } from "./CertificateSigningDialog";
import { loadPdf } from "./pdf";
vi.mock("./pdf", () => ({ loadPdf: vi.fn() }));

const bytes = new Uint8Array([1, 2]);
const cert = { id: "ab".repeat(32), holder: "Reader", stampName: "Reader", issuer: "Test", validUntil: "2099-01-01" };
const other = { ...cert, id: "cd".repeat(32), holder: "MARIA:12345678909", stampName: "Maria",
  taxId: { type: "CPF" as const, value: "123.456.789-09" } };
let pdf: PDFDocumentProxy;
let original: Uint8Array<ArrayBufferLike>;
beforeAll(async () => {
  const document = await PDFDocument.create();
  for (const angle of [0, 90, 180, 270, 90]) {
    const page = document.addPage([520, 740]);
    page.setCropBox(70, 90, 400, 600);
    page.setRotation(degrees(angle));
  }
  document.getPage(4).node.set(PDFName.of("UserUnit"), PDFNumber.of(2));
  document.addPage([120, 200]);
  const fractional = document.addPage();
  fractional.setMediaBox(-40, -60, 520, 840);
  fractional.setCropBox(-12.75, -20.625, 400.5, 600.125);
  fractional.setRotation(degrees(270));
  fractional.node.set(PDFName.of("UserUnit"), PDFNumber.of(2.75));
  const field = document.getForm().createTextField("Full name");
  field.setText("Original");
  field.addToPage(document.getPage(0), { x: 100, y: 500, width: 140, height: 24 });
  original = await document.save();
  pdf = await getDocument({ data: original.slice() }).promise;
  // PDF.js computes the real viewports. The desktop smoke test exercises canvas painting.
  for (let number = 1; number <= pdf.numPages; number++) {
    const page = await pdf.getPage(number);
    vi.spyOn(page, "render").mockImplementation(() => ({ promise: Promise.resolve(), cancel() {} }) as RenderTask);
  }
});
afterAll(async () => { await pdf?.loadingTask.destroy(); });

let host: HTMLDivElement;
let root: ReturnType<typeof createRoot>;
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  host = document.createElement("div");
  root = createRoot(host);
  vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue({
    measureText: (text: string) => ({ width: text.length * 6 }),
  } as CanvasRenderingContext2D);
});
afterEach(async () => {
  await act(async () => root.unmount());
  vi.mocked(HTMLCanvasElement.prototype.getContext).mockRestore();
  vi.mocked(loadPdf).mockReset();
  vi.unstubAllGlobals();
});

function dialog(page = 1, snapshot: ComponentProps<typeof CertificateSigningDialog>["snapshot"] = vi.fn(async () => ({ bytes, annotated: false })),
  sign = vi.fn<CertificateStore["sign"]>(async () => ({ bytes }))) {
  const store = { list: async () => ({ certificates: [cert, other] }), cancel: vi.fn(async () => true), sign };
  const onSigned = vi.fn();
  const render = (blocked?: string) => act(async () => root.render(<CertificateSigningDialog name="sample.pdf"
    pdf={pdf} currentPage={page} blocked={blocked} store={store} snapshot={snapshot} onSigned={onSigned}
    onClose={() => root.render(null)} />));
  return { render, snapshot, sign, onSigned, store };
}
const selectCertificate = async (id = cert.id) => act(async () => host.querySelector<HTMLInputElement>('input[value="' + id + '"]')!.click());
const submit = () => act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
const changeInput = (input: HTMLInputElement, value: string) => act(async () => {
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
});
const submitButton = () => host.querySelector<HTMLButtonElement>('button[type="submit"]')!;
const toggleStamp = () => act(async () => host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click());
const stampPage = (number: number) => host.querySelector<HTMLButtonElement>('[aria-label="Place stamp on page ' + number + '"]');

test("a visible stamp needs an explicit location; signing without one sends only the selected certificate", async () => {
  const { render, snapshot, sign, onSigned } = dialog(2);
  await render();
  await selectCertificate(other.id);
  expect(submitButton().disabled).toBe(true);
  expect(host.querySelector<HTMLInputElement>('input[type="checkbox"]')?.checked).toBe(true);
  expect(host.textContent).toContain("123.456.789-09");
  await submit();
  expect(sign).not.toHaveBeenCalled();
  await toggleStamp();
  expect(stampPage(2)).toBeNull();
  expect(submitButton().disabled).toBe(false);
  await submit();
  expect(snapshot).toHaveBeenCalledOnce();
  expect(sign.mock.calls[0][0]).toMatchObject({ id: other.id, data: bytes });
  expect(sign.mock.calls[0][0]).not.toHaveProperty("placement");
  expect(onSigned).toHaveBeenCalledWith(bytes);
});

test.each([
  [1, 200, 300, [240, 499, 470, 581]],  // 0°
  [2, 300, 200, [129, 400, 211, 630]],  // 90°
  [3, 200, 300, [70, 199, 300, 281]],   // 180°
  [4, 300, 200, [329, 150, 411, 380]],  // 270°
  [5, 300, 200, [149.5, 455, 190.5, 570]], // 90°, UserUnit 2
] as const)("clicking and nudging right on page %i sends its cropped PDF coordinates", async (number, width, height, rect) => {
  const { render, sign } = dialog(number);
  await render();
  await selectCertificate();
  const page = stampPage(number);
  expect(page).toBeTruthy();
  vi.spyOn(page!, "getBoundingClientRect").mockReturnValue(new DOMRect(40, 10, width, height));
  await act(async () => { page!.dispatchEvent(new MouseEvent("click", { bubbles: true, detail: 1,
    clientX: 40 + width * 0.7, clientY: 10 + height * 0.25 })); });
  await act(async () => { page!.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, key: "ArrowRight" })); });
  expect(submitButton().disabled).toBe(false);
  await submit();
  expect(sign.mock.calls[0][0].placement).toEqual({ pageNumber: number, rect });
});

test("changing pages clears the old position, small pages offer signing without a stamp, and reopening forgets the choice", async () => {
  const { render, sign } = dialog();
  await render();
  await selectCertificate();
  await act(async () => stampPage(1)?.click());
  expect(submitButton().disabled).toBe(false);
  const selector = host.querySelector<HTMLInputElement>('input[aria-label="Stamp page"]');
  expect(selector).toBeTruthy();
  await changeInput(selector!, "6");
  expect(submitButton().disabled).toBe(true);
  expect(host.textContent).toMatch(/too small/i);
  await act(async () => stampPage(6)?.click());
  await submit();
  expect(sign).not.toHaveBeenCalled();
  await toggleStamp();
  expect(submitButton().disabled).toBe(false);
  await act(async () => host.querySelector<HTMLButtonElement>('button[aria-label="Close"]')!.click());
  await render();
  expect(host.querySelector('input[type="radio"]:checked')).toBeNull();
  await selectCertificate();
  expect(host.querySelector<HTMLInputElement>('input[type="checkbox"]')?.checked).toBe(true);
  expect(stampPage(1)).toBeTruthy();
  expect(submitButton().disabled).toBe(true);
});

test("the preview renders edited fields and pending notes from the same revision that is signed", async () => {
  const changed = await PDFDocument.load(original);
  changed.getForm().getTextField("Full name").setText("Preenchido");
  const note = changed.context.register(changed.context.obj({ Type: "Annot", Subtype: "Text",
    Rect: [200, 300, 228, 328], Contents: PDFString.of("Previously unrendered note") }));
  changed.getPage(1).node.addAnnot(note);
  const data = await changed.save();
  vi.mocked(loadPdf).mockImplementationOnce(async bytes => {
    const copy = await getDocument({ data: bytes.slice() }).promise;
    for (const number of [1, 2]) {
      vi.spyOn(await copy.getPage(number), "render").mockImplementation(() => ({ promise: Promise.resolve(), cancel() {} }) as RenderTask);
    }
    return copy;
  });
  const snapshot = vi.fn(async () => ({ bytes: data, annotated: true }));
  const { render, sign } = dialog(1, snapshot);
  await render();
  await selectCertificate();
  expect(loadPdf).toHaveBeenCalledOnce();
  const copy: PDFDocumentProxy = await act(async () => await vi.mocked(loadPdf).mock.results[0].value);
  const first = await copy.getPage(1), second = await copy.getPage(2);
  expect((await first.getAnnotations()).some(a => a.fieldValue === "Preenchido")).toBe(true);
  expect(first.render).toHaveBeenCalledOnce();
  await changeInput(host.querySelector<HTMLInputElement>('input[aria-label="Stamp page"]')!, "2");
  expect((await second.getAnnotations()).some(a => a.contentsObj?.str === "Previously unrendered note")).toBe(true);
  expect(second.render).toHaveBeenCalledOnce();
  await act(async () => stampPage(2)?.click());
  await submit();
  expect(snapshot).toHaveBeenCalledOnce();
  expect(sign.mock.calls[0][0].data).toBe(data);
});

test("closing while an edited preview opens aborts it and releases a late PDF", async () => {
  const data = await pdf.getData();
  const copy = await getDocument({ data: data.slice() }).promise;
  const destroy = vi.spyOn(copy.loadingTask, "destroy");
  let finish!: () => void;
  vi.mocked(loadPdf).mockImplementationOnce(async () => {
    await new Promise<void>(resolve => { finish = resolve; });
    return copy;
  });
  const { render, sign, onSigned } = dialog(1, vi.fn(async () => ({ bytes: data, annotated: true })));
  await render();
  await selectCertificate();
  expect(loadPdf).toHaveBeenCalledOnce();
  const signal = vi.mocked(loadPdf).mock.calls[0][1];
  await act(async () => host.querySelector<HTMLButtonElement>('button[aria-label="Close"]')!.click());
  expect(signal.aborted).toBe(true);
  await act(async () => { finish(); });
  expect(destroy).toHaveBeenCalledOnce();
  expect(sign).not.toHaveBeenCalled();
  expect(onSigned).not.toHaveBeenCalled();
});

test("resizing and clicking the far corner keep a rotated stamp inside a fractional CropBox", async () => {
  const { render, sign } = dialog(7);
  await render();
  await selectCertificate();
  const paper = stampPage(7)!;
  vi.spyOn(paper, "getBoundingClientRect").mockReturnValue(new DOMRect(10, 20, 320, 240));
  await act(async () => paper.click());
  const range = host.querySelector<HTMLInputElement>('input[type="range"]')!;
  await changeInput(range, "130");
  await act(async () => { paper.dispatchEvent(new MouseEvent("click", { bubbles: true, detail: 1, clientX: 330, clientY: 260 })); });
  await submit();
  const [xmin, ymin, xmax, ymax] = sign.mock.calls[0][0].placement!.rect;
  expect(xmin).toBe(-12.75);
  expect(ymin).toBe(-20.625);
  expect(xmax).toBeCloseTo(6.88636363636, 8);
  expect(ymax).toBeCloseTo(26.64772727273, 8);
});

test("a late render from an earlier page cannot replace the chosen page's viewport", async () => {
  let finish!: () => void;
  const pending = new Promise<void>(resolve => { finish = resolve; });
  const cancel = vi.fn();
  vi.mocked((await pdf.getPage(2)).render).mockImplementationOnce(() => ({ promise: pending, cancel }) as unknown as RenderTask);
  const { render, sign } = dialog();
  await render();
  await selectCertificate();
  const selector = host.querySelector<HTMLInputElement>('input[aria-label="Stamp page"]')!;
  await changeInput(selector, "2");
  expect(stampPage(2)?.disabled).toBe(true);
  await changeInput(selector, "3");
  expect(cancel).toHaveBeenCalledOnce();
  await act(async () => { finish(); });
  await act(async () => stampPage(3)?.click());
  await submit();
  expect(sign.mock.calls[0][0].placement).toEqual({ pageNumber: 3, rect: [155, 349, 385, 431] });
});

test.each([
  ["snapshot", "document change"], ["signature", "document change"], ["snapshot", "cancel"], ["signature", "cancel"],
])("a pending %s is discarded on %s", async (stage, action) => {
  let finish!: () => void;
  const wait = new Promise<void>(resolve => { finish = resolve; });
  const { render, store, onSigned } = dialog(1,
    vi.fn(async () => { if (stage === "snapshot") await wait; return { bytes, annotated: false }; }),
    vi.fn(async () => { if (stage === "signature") await wait; return { bytes }; }));
  await render();
  await selectCertificate();
  await toggleStamp();
  await submit();
  expect(store.sign).toHaveBeenCalledTimes(stage === "signature" ? 1 : 0);
  if (action === "cancel") {
    await act(async () => host.querySelector<HTMLButtonElement>('button[aria-label="Close"]')!.click());
  } else {
    await render("Save the changed document first.");
  }
  expect(store.cancel).toHaveBeenCalledTimes(1);
  await act(async () => { finish(); });
  expect(store.sign).toHaveBeenCalledTimes(stage === "signature" ? 1 : 0);
  expect(onSigned).not.toHaveBeenCalled();
});
