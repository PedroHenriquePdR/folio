import { useLayoutEffect, useRef, useState } from "react";
import { Modal } from "./Dialogs";

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
  pdf_unsupported: "Folio cannot preserve this PDF’s structure when signing.",
  cms_size: "This certificate chain is too large to embed in the PDF.",
  invalid_request: "Choose a PDF of up to 300 MB.",
};
const fallbackError = "Folio couldn’t sign this copy. Check your certificate and try again.";

interface Props {
  store: CertificateStore;
  name: string;
  blocked?: string;
  snapshot(): Promise<Uint8Array | undefined>;
  onSigned(bytes: Uint8Array): void;
  onClose(): void;
}

export function CertificateSigningDialog({ store, name, blocked, snapshot, onSigned, onClose }: Props) {
  const [certs, setCerts] = useState<SigningCertificate[]>([]);
  const [selected, setSelected] = useState("");
  const [phase, setPhase] = useState<"loading" | "locked" | "choose" | "signing">("loading");
  const [error, setError] = useState("");
  const password = useRef("");
  const passwordField = useRef<HTMLInputElement>(null);
  const request = useRef("");
  const generation = useRef(0);

  async function list(secret?: string) {
    const ticket = ++generation.current;
    setPhase("loading"); setError(""); setSelected("");
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

  async function sign() {
    if (blocked || phase !== "choose" || !selected || request.current) return;
    const requestId = crypto.randomUUID();
    request.current = requestId;
    setPhase("signing"); setError("");
    try {
      const data = await snapshot();
      if (request.current !== requestId) return;
      if (!data) throw new Error();
      const result = await store.sign({ requestId, id: selected, name, data, password: password.current || undefined });
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
          <fieldset disabled={phase === "signing"}>
            <legend>Installed certificates</legend>
            {certs.map(c => <label className="certificate-choice" key={c.id}>
              <input type="radio" name="certificate" value={c.id} checked={selected === c.id} onChange={() => setSelected(c.id)} />
              <span><strong>{c.holder}</strong><small>Issued by {c.issuer}</small>
                <small>Expires {new Date(c.validUntil).toLocaleDateString()} · {c.id.slice(-12).toUpperCase()}</small></span>
            </label>)}
          </fieldset>
        </> : !error && <p>No eligible A1 certificate was found. Import your .pfx or .p12 with its private key into the local certificate store, then reopen this dialog.</p>)}
        {phase === "signing" && <p role="status">Preparing your signed copy…</p>}
        {error && <p role="alert" className="form-error">{error}</p>}
      </>}
      <div className="form-actions">
        <button type="button" className="btn ghost" onClick={close}>Cancel</button>
        {!blocked && <button type="submit" className="btn primary" disabled={!locked && (phase !== "choose" || !selected)}>
          {locked ? "Unlock" : "Sign copy"}
        </button>}
      </div>
    </form>
  </Modal>;
}
