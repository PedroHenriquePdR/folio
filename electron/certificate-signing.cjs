const { spawn, fork } = require("node:child_process");
const path = require("node:path");
const { MAX_DOCUMENT_BYTES } = require("./document-files.cjs");
const { safePdfName } = require("./filenames.cjs");

const MAX_CMS_BYTES = 32 * 1024;
const ID = /^[0-9a-f]{64}$/;
const fail = code => Object.assign(new Error(code), { code });
const errors = new Set(["invalid_request", "unavailable", "no_store", "password_required", "certificate_unavailable",
  "sign_failed", "pdf_invalid", "pdf_encrypted", "pdf_already_signed", "pdf_restricted_field", "pdf_a1", "pdf_xfa",
  "pdf_unsupported", "pdf_signature_failed", "cms_size", "invalid_placement", "stamp_glyph"]);
const errorCode = code => errors.has(code) ? code : "sign_failed";
const validPassword = password => password === undefined || (typeof password === "string" && Buffer.byteLength(password) <= 1024 && !password.includes("\0"));
const displayText = value => typeof value === "string" ? value.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, " ").trim().slice(0, 256) : "";

function validPlacement(value) {
  if (!value || !Number.isSafeInteger(value.pageNumber) || value.pageNumber < 1) return false;
  const r = value.rect;
  return Array.isArray(r) && r.length === 4 && r.every(Number.isFinite) && r[0] < r[2] && r[1] < r[3];
}

function publicIdentity(cert) {
  const taxId = cert.taxId;
  const formats = { CPF: /^\d{3}\.\d{3}\.\d{3}-\d{2}$/, CNPJ: /^[A-Z0-9]{2}\.[A-Z0-9]{3}\.[A-Z0-9]{3}\/[A-Z0-9]{4}-\d{2}$/ };
  const hasTaxId = taxId && Object.hasOwn(formats, taxId.type) && typeof taxId.value === "string" && formats[taxId.type].test(taxId.value);
  return { id: cert.id, holder: displayText(cert.holder), issuer: displayText(cert.issuer), validUntil: cert.validUntil,
    stampName: displayText(cert.stampName) || "Titular do certificado",
    ...(hasTaxId ? { taxId: { type: taxId.type, value: taxId.value } } : {}) };
}

function runCertificateHelper(binary, header, data, signal, env = process.env) {
  signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    const child = spawn(binary, [], { stdio: ["pipe", "pipe", "ignore"], windowsHide: true, env, signal });
    const chunks = [];
    let size = 0;
    const timer = setTimeout(() => { child.kill(); reject(fail("sign_failed")); }, 60_000);
    child.once("error", error => reject(fail(error.code === "ENOENT" || error.code === "EACCES" ? "unavailable" : "sign_failed")));
    child.stdout.on("data", chunk => {
      size += chunk.length;
      if (size <= 1024 * 1024) chunks.push(chunk);
      else { child.kill(); reject(fail("sign_failed")); }
    });
    child.once("close", code => {
      clearTimeout(timer);
      try {
        if (code !== 0 || size > 1024 * 1024) throw fail("sign_failed");
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch { reject(fail("sign_failed")); }
    });
    // A rejected request can close stdin while a large document is still being written.
    child.stdin.on("error", () => {});
    child.stdin.write(JSON.stringify(header) + "\n");
    child.stdin.end(data);
  });
}

// Keep parsing and serializing the PDF off the UI thread. The PDF process never receives store credentials.
function processCertificatePdf(bytes, sign, signal, appearance) {
  signal.throwIfAborted();
  const script = path.join(__dirname, "certificate-pdf-worker.cjs");
  const utility = process.versions.electron && process.type === "browser";
  const worker = utility
    ? require("electron").utilityProcess.fork(script, [], { serviceName: "Folio PDF signature", stdio: "ignore", execArgv: ["--max-old-space-size=768"] })
    : fork(script, [], { serialization: "advanced", stdio: ["ignore", "ignore", "ignore", "ipc"], execArgv: ["--max-old-space-size=768"] });
  const send = value => utility ? worker.postMessage(value) : worker.send(value);
  return new Promise((resolve, reject) => {
    let done = false, signing = false;
    const finish = (error, value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      worker.kill();
      if (error) reject(error);
      else resolve(value);
    };
    const abort = () => finish(fail("sign_failed"));
    const timer = setTimeout(abort, 120_000);
    signal.addEventListener("abort", abort, { once: true });
    worker.once("error", abort);
    worker.once("exit", abort);
    worker.on("message", async message => {
      if (done) return;
      try {
        if (message.error) throw fail(errorCode(message.error));
        if (!signing && message.covered instanceof Uint8Array && message.covered.length <= MAX_DOCUMENT_BYTES + 1024 * 1024) {
          signing = true;
          const cms = await sign(message.covered);
          if (!done) send({ cms });
        } else if (signing && message.bytes instanceof Uint8Array && message.bytes.length >= bytes.length) {
          finish(null, message.bytes);
        } else throw fail("pdf_signature_failed");
      } catch (error) { finish(error); }
    });
    try { send({ pdf: bytes, appearance }); } catch (error) { finish(error); }
  });
}

function createCertificateService({ run, confirm, processPdf = processCertificatePdf }) {
  let active;
  async function list(password, signal) {
    if (!validPassword(password)) return { error: "invalid_request" };
    try {
      const result = await run({ action: "list", password }, undefined, signal);
      if (result?.error) return { error: errorCode(result.error) };
      if (!Array.isArray(result?.certificates)) return { error: "sign_failed" };
      const certificates = result.certificates.filter(c => c && ID.test(c.id) && Date.parse(c.validUntil) > Date.now())
        .map(publicIdentity);
      return { certificates };
    } catch (error) { return { error: errorCode(error?.code) }; }
  }
  return {
    list,
    cancel(requestId) {
      if (!active || requestId !== active.id) return false;
      active.controller.abort();
      return true;
    },
    async sign(input) {
      if (!input || typeof input.requestId !== "string" || !/^[\w-]{1,80}$/.test(input.requestId) ||
          typeof input.id !== "string" || !ID.test(input.id) || !validPassword(input.password) ||
          typeof input.name !== "string" || !input.name.trim() || input.name.length > 1024 ||
          !(input.data instanceof Uint8Array) || input.data.length > MAX_DOCUMENT_BYTES ||
          !Buffer.from(input.data.buffer, input.data.byteOffset, Math.min(5, input.data.length)).equals(Buffer.from("%PDF-"))) {
        return { error: "invalid_request" };
      }
      if (input.placement !== undefined && !validPlacement(input.placement)) return { error: "invalid_placement" };
      if (active) return { error: "busy" };
      const controller = new AbortController();
      const { signal } = controller;
      active = { id: input.requestId, controller };
      try {
        const bytes = Buffer.from(input.data);
        const { id, password } = input;
        const placement = input.placement && { pageNumber: input.placement.pageNumber, rect: [...input.placement.rect] };
        const name = safePdfName(displayText(input.name), "document.pdf");
        const result = await list(password, signal);
        signal.throwIfAborted();
        if (result.error) return result;
        const cert = result.certificates.find(c => c.id === id);
        if (!cert) return { error: "certificate_unavailable" };
        const confirmed = await confirm(name, cert, signal, placement);
        if (!confirmed || signal.aborted) return { cancelled: true };
        const now = new Date();
        const appearance = placement && { placement, holder: cert.stampName, taxId: cert.taxId,
          signedAt: now.toISOString(), utcOffsetMinutes: -now.getTimezoneOffset() };
        const signed = await processPdf(bytes, async covered => {
          signal.throwIfAborted();
          const response = await run({ action: "sign", id, password }, covered, signal);
          signal.throwIfAborted();
          if (response?.error) throw fail(errorCode(response.error));
          const value = response?.cms;
          if (typeof value !== "string" || !value.length || value.length > 4 * Math.ceil(MAX_CMS_BYTES / 3)) throw fail("sign_failed");
          const cms = Buffer.from(value, "base64");
          if (cms.length > MAX_CMS_BYTES || cms.toString("base64") !== value) throw fail("sign_failed");
          return cms;
        }, signal, appearance);
        return signal.aborted ? { cancelled: true } : { bytes: signed };
      } catch (error) { return signal.aborted ? { cancelled: true } : { error: errorCode(error?.code) }; }
      finally { controller.abort(); active = undefined; }
    },
  };
}

function registerCertificateSigning(handle, getWindow, { app, dialog, runHelper = runCertificateHelper } = require("electron")) {
  const filename = process.platform === "win32" ? "folio-certsign.exe" : "folio-certsign";
  const binary = app.isPackaged ? path.join(process.resourcesPath, "certsign", filename) : path.join(__dirname, "..", "native-bin", filename);
  const service = createCertificateService({
    run: (header, data, signal) => runHelper(binary, header, data, signal),
    confirm: async (name, cert, signal, placement) => {
      const parent = getWindow();
      if (!parent || parent.isDestroyed()) return false;
      const mark = placement ? `Visible signature on page ${placement.pageNumber}` : "Sign without a visible mark";
      const identifier = placement && cert.taxId ? `\n${cert.taxId.type}: ${cert.taxId.value}` : "";
      const answer = await dialog.showMessageBox(parent, { type: "question", title: "Sign with a certificate",
        message: `Sign a copy of “${name}”?`, detail: `Holder: ${cert.holder}\nIssuer: ${cert.issuer}\nSHA-256: ${cert.id}\n${mark}${identifier}`,
        buttons: ["Cancel", "Sign copy"], defaultId: 0, cancelId: 0, noLink: true, signal });
      return answer.response === 1;
    },
  });
  handle("folio:certificates-list", (_event, password) => service.list(password));
  handle("folio:certificates-sign", async (event, input) => {
    const sender = event.sender;
    const abort = () => service.cancel(input?.requestId);
    const navigation = details => { if (details.isMainFrame && !details.isSameDocument) abort(); };
    sender.once("destroyed", abort);
    sender.once("render-process-gone", abort);
    sender.on("did-start-navigation", navigation);
    try { return await service.sign(input); }
    finally {
      sender.removeListener("destroyed", abort);
      sender.removeListener("render-process-gone", abort);
      sender.removeListener("did-start-navigation", navigation);
    }
  });
  handle("folio:certificates-cancel", (_event, requestId) => service.cancel(requestId));
}

module.exports = { createCertificateService, runCertificateHelper, registerCertificateSigning };
