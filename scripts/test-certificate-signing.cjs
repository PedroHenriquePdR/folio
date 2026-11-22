const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createCertificateService } = require("../electron/certificate-signing.cjs");

const id = "ab".repeat(32);
const cert = { id, holder: "Test holder", stampName: "Test holder", issuer: "Test issuer", validUntil: "2099-01-01T00:00:00Z" };
const pdf = Buffer.from("%PDF-1.7 fixture");
const input = () => ({ id, data: Buffer.from(pdf), name: "contract.pdf", requestId: "request-1" });
function fixture(overrides = {}) {
  const calls = [];
  const service = createCertificateService({
    run: async (header, data) => {
      calls.push({ header, data });
      return header.action === "list" ? { certificates: [cert] } : { cms: "MAMCAQE=" };
    },
    confirm: async () => true,
    processPdf: async (bytes, sign) => {
      const cms = await sign(Buffer.concat([bytes, Buffer.from(" covered range")]));
      assert.deepEqual(cms, Buffer.from("MAMCAQE=", "base64"));
      return Buffer.from("%PDF-signed");
    },
    ...overrides,
  });
  return { service, calls };
}

test("confirms the installed identity and signs the immutable document snapshot", async () => {
  const request = input();
  const { service, calls } = fixture({ confirm: async (name, identity) => {
    assert.equal(name, "contract.pdf");
    assert.deepEqual(identity, cert);
    request.data.fill(0);
    return true;
  } });
  request.password = "temporary";
  request.holder = "Untrusted label";
  assert.deepEqual(await service.sign(request), { bytes: Buffer.from("%PDF-signed") });
  assert.deepEqual(calls, [
    { header: { action: "list", password: "temporary" }, data: undefined },
    { header: { action: "sign", id, password: "temporary" }, data: Buffer.concat([pdf, Buffer.from(" covered range")]) },
  ]);
});

test("declining confirmation makes no private-key request", async () => {
  const { service, calls } = fixture({ confirm: async () => false });
  assert.deepEqual(await service.sign(input()), { cancelled: true });
  assert.deepEqual(calls.map(c => c.header.action), ["list"]);
});

test("only immutable placement and the re-read identity reach the PDF worker after approval", async () => {
  const taxId = { type: "CPF", value: "123.456.789-09" };
  const local = { ...cert, stampName: "Titular de teste", taxId };
  const placement = { pageNumber: 2, rect: [40, 25, 270, 107] };
  const request = { ...input(), placement: structuredClone(placement), holder: "Renderer",
    taxId: { type: "CPF", value: "000.000.000-00" }, signedAt: "1900-01-01T00:00:00.000Z" };
  let appearance;
  const before = Date.now();
  const { service } = fixture({
    run: async () => ({ certificates: [local] }),
    confirm: async (_name, identity, _signal, location) => {
      request.placement.rect.fill(0);
      request.placement.pageNumber = 1;
      assert.deepEqual(location, placement);
      assert.equal(identity.stampName, local.stampName);
      return true;
    },
    processPdf: async (bytes, _sign, _signal, options) => { appearance = options; return bytes; },
  });
  assert.deepEqual(await service.sign(request), { bytes: pdf });
  assert.deepEqual(appearance.placement, placement);
  assert.equal(appearance.holder, local.stampName);
  assert.deepEqual(appearance.taxId, taxId);
  const instant = new Date(appearance.signedAt);
  assert.ok(instant.getTime() >= before && instant.getTime() <= Date.now());
  assert.equal(appearance.utcOffsetMinutes, -instant.getTimezoneOffset());
});

test("malformed placements stop before asking for a certificate or signature", async () => {
  const { service, calls } = fixture();
  for (const placement of [null, {}, { pageNumber: 0, rect: [1, 1, 2, 2] }, { pageNumber: 1.5, rect: [1, 1, 2, 2] },
    { pageNumber: 1, rect: [0, 0, 100] }, { pageNumber: 1, rect: [10, 0, 10, 50] },
    { pageNumber: 2, rect: [20, NaN, 180, 78] }, { pageNumber: 2, rect: [0, 0, Infinity, 100] }]) {
    assert.deepEqual(await service.sign({ ...input(), placement }), { error: "invalid_placement" });
  }
  assert.equal(calls.length, 0);
});

test("the printed date uses the signing instant, including a local date change and offset minutes", async () => {
  const { stampLines } = await import("../electron/certificate-stamp.mjs");
  const stamp = stampLines("João", { type: "CPF", value: "123.456.789-09" }, "2026-01-01T01:02:03Z", -210);
  assert.deepEqual(stamp, ["Assinado digitalmente", "João", "CPF: 123.456.789-09", "31/12/2025 21:32:03 UTC-03:30", "ICP-Brasil"]);
  assert.deepEqual(stampLines("Empresa", undefined, "2026-12-31T23:59:59Z", 330).slice(2),
    ["01/01/2027 05:29:59 UTC+05:30", "ICP-Brasil"]);
});

test("invalid input, a missing certificate and a locked store stop before confirmation", async () => {
  let confirmed = false;
  const { service, calls } = fixture({ confirm: async () => { confirmed = true; return true; } });
  for (const changes of [{ id: "bad" }, { data: [37, 80] }, { data: Buffer.from("not PDF") }, { password: 3 }, { requestId: "" }]) {
    assert.deepEqual(await service.sign({ ...input(), ...changes }), { error: "invalid_request" });
  }
  assert.equal(calls.length, 0);
  assert.deepEqual(await service.sign({ ...input(), id: "cd".repeat(32) }), { error: "certificate_unavailable" });
  assert.equal(confirmed, false);
  const locked = fixture({ run: async () => ({ error: "password_required" }), confirm: () => assert.fail() });
  assert.deepEqual(await locked.service.list(), { error: "password_required" });
  assert.deepEqual(await locked.service.sign(input()), { error: "password_required" });
});

test("only the active request can cancel and a delayed approval cannot start signing", async () => {
  let approve, entered;
  const waiting = new Promise(resolve => { entered = resolve; });
  const { service, calls } = fixture({ confirm: () => new Promise(resolve => { approve = resolve; entered(); }) });
  const first = service.sign(input());
  await waiting;
  assert.deepEqual(await service.sign({ ...input(), requestId: "request-2" }), { error: "busy" });
  assert.equal(service.cancel("request-2"), false);
  assert.equal(service.cancel("request-1"), true);
  approve(true);
  assert.deepEqual(await first, { cancelled: true });
  assert.deepEqual(calls.map(c => c.header.action), ["list"]);
});

test("expiry, refusal by the key and malformed CMS do not produce signed bytes", async () => {
  const expired = fixture({ run: async () => ({ certificates: [{ ...cert, validUntil: "2000-01-01" }] }), confirm: () => assert.fail() });
  assert.deepEqual(await expired.service.sign(input()), { error: "certificate_unavailable" });
  for (const [result, code] of [[{ error: "password_required" }, "password_required"], [{ cms: "*" }, "sign_failed"]]) {
    const { service } = fixture({ run: async header => header.action === "sign" ? result : { certificates: [cert] } });
    assert.deepEqual(await service.sign(input()), { error: code });
  }
});

test("the registered handler cancels on a main-frame navigation while native approval is pending", async () => {
  const { EventEmitter } = require("node:events");
  const { registerCertificateSigning } = require("../electron/certificate-signing.cjs");
  const handlers = new Map();
  const sender = new EventEmitter();
  let entered, answer, promptSignal;
  const waiting = new Promise(resolve => { entered = resolve; });
  registerCertificateSigning((name, fn) => handlers.set(name, fn), () => ({ isDestroyed: () => false }), {
    app: { isPackaged: false },
    dialog: { showMessageBox: (_parent, options) => {
      promptSignal = options.signal;
      assert.equal(options.defaultId, 0);
      assert.match(options.detail, /Test issuer/);
      assert.match(options.detail, /[Pp]age 2/);
      entered();
      return new Promise(resolve => { answer = resolve; });
    } },
    runHelper: async (_binary, header) => { assert.equal(header.action, "list"); return { certificates: [cert] }; },
  });
  const result = handlers.get("folio:certificates-sign")({ sender }, { ...input(), placement: { pageNumber: 2, rect: [0, 0, 230, 82] } });
  await waiting;
  sender.emit("did-start-navigation", { isMainFrame: false, isSameDocument: false }, "app://reader/");
  sender.emit("did-start-navigation", { isMainFrame: true, isSameDocument: true }, "app://reader/#p2");
  assert.equal(promptSignal.aborted, false);
  sender.emit("did-start-navigation", { isMainFrame: true, isSameDocument: false }, "app://reader/");
  assert.equal(promptSignal.aborted, true);
  answer({ response: 1 });
  assert.deepEqual(await result, { cancelled: true });
  assert.equal(sender.listenerCount("did-start-navigation"), 0);
});
