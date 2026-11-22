// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, test, vi } from "vitest";
import { CertificateSigningDialog } from "./CertificateSigningDialog";

test.each(["snapshot", "signature"])("a changed document discards a pending %s", async stage => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const container = document.createElement("div");
  const root = createRoot(container);
  const cert = { id: "ab".repeat(32), holder: "Reader", issuer: "Test", validUntil: "2099-01-01" };
  let finish!: () => void;
  const wait = new Promise<void>(resolve => { finish = resolve; });
  const bytes = new Uint8Array([1, 2]);
  const snapshot = async () => { if (stage === "snapshot") await wait; return bytes; };
  const onSigned = vi.fn();
  const store = { list: async () => ({ certificates: [cert] }), cancel: vi.fn(async () => true),
    sign: vi.fn(async () => { if (stage === "signature") await wait; return { bytes }; }) };
  const render = (blocked?: string) => act(async () => root.render(<CertificateSigningDialog name="sample.pdf"
    blocked={blocked} store={store} snapshot={snapshot} onSigned={onSigned} onClose={() => {}} />));
  try {
    await render();
    await act(async () => { container.querySelector<HTMLInputElement>('input[type="radio"]')!.click(); });
    await act(async () => { container.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
    expect(store.sign).toHaveBeenCalledTimes(stage === "signature" ? 1 : 0);
    await render("Save the changed document first.");
    expect(store.cancel).toHaveBeenCalledTimes(1);
    await act(async () => { finish(); });
    expect(store.sign).toHaveBeenCalledTimes(stage === "signature" ? 1 : 0);
    expect(onSigned).not.toHaveBeenCalled();
  } finally {
    await act(async () => root.unmount());
    vi.unstubAllGlobals();
  }
});
