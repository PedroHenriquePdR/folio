import { useEffect, useEffectEvent, useLayoutEffect, useRef, useState } from "react";
import { Modal } from "./Dialogs";
import { CertificateStampPlacement } from "./CertificateStampPlacement";
import { loadPdf, type PDFDocumentProxy } from "./pdf";

const messages: Record<string, string> = {
  no_store: "Couldn’t find the local certificate store. Import your A1 certificate and reopen this dialog.",
  certificate_unavailable: "This certificate is no longer available. Reopen this dialog to choose another.",
  unavailable: "The certificate signer could not start. Check your Folio installation.",
  busy: "Another document is being signed. Try again when it finishes.",
  pdf_invalid: "Folio couldn’t read this PDF. It may be damaged or password-protected.",
  pdf_encrypted: "This PDF is encrypted. Open an unencrypted copy to sign it.",
  pdf_already_signed: "This PDF already has a digital signature or certification. This version supports the first signature only.",
  pdf_restricted_field: "This PDF has signature field requirements that Folio cannot fulfill.",
  pdf_a1: "This PDF/A-1 file cannot use the required ICP-Brasil PDF extensions. Open a PDF 1.7 copy to sign it.",
  pdf_xfa: "Folio cannot sign this XFA form.",
  stamp_glyph: "The stamp font can’t display this certificate holder’s name. Turn off the visible stamp to sign this copy.",
  invalid_placement: "The stamp does not fit on this page. Choose its position again.",
  pdf_unsupported: "Folio cannot preserve this PDF’s structure when signing.",
  cms_size: "This certificate chain is too large to embed in the PDF.",
  invalid_request: "Choose a PDF of up to 300 MB.",
};
const fallbackError = "Folio couldn’t sign this copy. Check your certificate and try again.";

interface Revision { bytes: Uint8Array; annotated: boolean }

interface Props {
  store: CertificateStore;
  pdf: PDFDocumentProxy;
  currentPage: number;
  name: string;
  blocked?: string;
  snapshot(): Promise<Revision | null>;
  onSigned(bytes: Uint8Array): void;
  onClose(): void;
}

export function CertificateSigningDialog({ store, pdf, currentPage, name, blocked, snapshot, onSigned, onClose }: Props) {
  const [certs, setCerts] = useState<SigningCertificate[]>([]);
  const [selected, setSelected] = useState("");
  const [visibleStamp, setVisibleStamp] = useState(true);
  const [placement, setPlacement] = useState<CertificatePlacement>();
  const [pageInput, setPageInput] = useState(String(currentPage));
  const certificate = certs.find(c => c.id === selected);
  const [phase, setPhase] = useState<"loading" | "locked" | "choose" | "signing">("loading");
  const [error, setError] = useState("");
  const password = useRef("");
  const passwordField = useRef<HTMLInputElement>(null);
  const request = useRef("");
  const generation = useRef(0);
  const revision = useRef<Promise<Revision> | undefined>(undefined);
  const previewWork = useRef<AbortController | undefined>(undefined);
  const [preview, setPreview] = useState<PDFDocumentProxy | "failed">();

  // currentBytes also includes marks on pages the reader hasn't rendered. Sign the exact
  // revision used for placement, and share an in-flight snapshot if the stamp is toggled.
  function readRevision() {
    if (!revision.current) {
      const pending = snapshot().then(copy => {
        if (!copy) throw new Error("No document snapshot");
        return copy;
      });
      revision.current = pending;
      void pending.catch(() => { if (revision.current === pending) revision.current = undefined; });
    }
    return revision.current;
  }
  const readPreviewRevision = useEffectEvent(readRevision);
  const wantsPreview = !!certificate && visibleStamp && !blocked && (phase === "choose" || phase === "signing");
  useEffect(() => {
    if (!wantsPreview) { setPreview(undefined); return; }
    const controller = new AbortController();
    previewWork.current = controller;
    let owned: PDFDocumentProxy | undefined;
    void (async () => {
      const copy = await readPreviewRevision();
      if (controller.signal.aborted) return;
      if (copy.annotated) {
        const loaded = await loadPdf(copy.bytes, controller.signal);
        if (controller.signal.aborted) { await loaded.loadingTask.destroy(); return; }
        owned = loaded;
      }
      setPreview(owned ?? pdf);
    })().catch(() => { if (!controller.signal.aborted) setPreview("failed"); });
    return () => {
      controller.abort();
      previewWork.current = undefined;
      if (owned) void owned.loadingTask.destroy().catch(() => {});
    };
  }, [pdf, wantsPreview]);

  async function list(secret?: string) {
    const ticket = ++generation.current;
    setPhase("loading"); setError(""); setSelected(""); setCerts([]);
    setPlacement(undefined); setVisibleStamp(true); setPageInput(String(currentPage));
    try {
      const result = await store.list(secret);
      if (ticket !== generation.current) return;
      if ("certificates" in result) {
        password.current = secret ?? "";
        setCerts(result.certificates);
      } else if (result.error === "password_required") {
        setError(secret ? "The store is still locked. Check the password and try again." : "");
        setPhase("locked");
        return;
      } else setError(messages[result.error] ?? fallbackError);
    } catch {
      if (ticket !== generation.current) return;
      setError(messages.unavailable);
    }
    setPhase("choose");
  }
  function stop() {
    generation.current++;
    previewWork.current?.abort();
    revision.current = undefined;
    password.current = "";
    const requestId = request.current;
    request.current = "";
    if (requestId) void store.cancel(requestId).catch(() => {});
  }
  function close() { stop(); onClose(); }
  useLayoutEffect(() => {
    if (!blocked) void list();
    return stop;
  }, [store, blocked]);

  const ready = !blocked && phase === "choose" && !!certificate &&
    (!visibleStamp || (preview && preview !== "failed" && placement?.pageNumber === Number(pageInput)));
  async function sign() {
    if (!ready || !certificate || request.current) return;
    const requestId = crypto.randomUUID();
    request.current = requestId;
    setPhase("signing"); setError("");
    try {
      const { bytes: data } = await readRevision();
      if (request.current !== requestId) return;
      const result = await store.sign({ requestId, id: certificate.id, name, data, password: password.current || undefined,
        ...(visibleStamp && placement ? { placement } : {}) });
      if (request.current !== requestId) return;
      if ("bytes" in result) { onSigned(result.bytes); return; }
      if ("error" in result) {
        if (result.error === "password_required") {
          password.current = "";
          setPhase("locked");
          return;
        }
        setError(messages[result.error] ?? fallbackError);
      }
    } catch {
      if (request.current !== requestId) return;
      setError(fallbackError);
    } finally { if (request.current === requestId) request.current = ""; }
    setPhase("choose");
  }

  const locked = phase === "locked";
  return <Modal title="Sign with a certificate" onClose={close}>
    <form className="password-form certificate-form" onSubmit={event => {
      event.preventDefault();
      if (locked) void list(passwordField.current?.value);
      else void sign();
    }}>
      {blocked ? <p>{blocked}</p> : <>
        {phase === "loading" && <p role="status">Reading installed certificates…</p>}
        {locked && <label>Certificate store password
          <input ref={passwordField} type="password" autoComplete="off" autoFocus required />
        </label>}
        {(phase === "choose" || phase === "signing") && (certs.length ? <>
          <p>Choose the ICP-Brasil A1 certificate to sign a copy of <strong>{name}</strong>.</p>
          <div className={certificate && visibleStamp ? "certificate-workspace" : undefined}>
            <div className="certificate-options">
              <fieldset disabled={phase === "signing"}>
                <legend>Installed certificates</legend>
                {certs.map(c => <label className="certificate-choice" key={c.id}>
                  <input type="radio" name="certificate" value={c.id} checked={selected === c.id}
                    onChange={() => { setSelected(c.id); setPlacement(undefined); }} />
                  <span><strong>{c.holder}</strong><small>Issued by {c.issuer}</small>
                    <small>Expires {new Date(c.validUntil).toLocaleDateString()} · {c.id.slice(-12).toUpperCase()}</small></span>
                </label>)}
              </fieldset>
              {certificate && <label className="certificate-visible">
                <input type="checkbox" checked={visibleStamp} disabled={phase === "signing"} onChange={event => {
                  setVisibleStamp(event.target.checked); setPlacement(undefined);
                }} /> Add a visible stamp
              </label>}
            </div>
            {wantsPreview && certificate && (preview && preview !== "failed" ?
              <CertificateStampPlacement pdf={preview} pageInput={pageInput} certificate={certificate}
                placement={placement} disabled={phase === "signing"} onPlace={setPlacement}
                onPage={value => { setPlacement(undefined); setPageInput(value); }} /> :
              <p className="certificate-page" role={preview === "failed" ? "alert" : "status"}>{preview === "failed"
                ? "Couldn’t prepare the document preview. Turn the visible stamp off and on to try again."
                : "Preparing document preview…"}</p>)}
          </div>
        </> : !error && <p>No eligible A1 certificate was found. Import your .pfx or .p12 with its private key into the local certificate store, then reopen this dialog.</p>)}
        {phase === "signing" && <p role="status">Preparing your signed copy…</p>}
        {error && <p role="alert" className="form-error">{error}</p>}
      </>}
      <div className="form-actions">
        <button type="button" className="btn ghost" onClick={close}>Cancel</button>
        {!blocked && <button type="submit" className="btn primary" disabled={!locked && !ready}>
          {locked ? "Unlock" : "Sign copy"}
        </button>}
      </div>
    </form>
  </Modal>;
}
