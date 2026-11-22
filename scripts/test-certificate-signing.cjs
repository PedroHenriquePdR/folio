const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createCertificateService } = require("../electron/certificate-signing.cjs");

const id = "ab".repeat(32);
const cert = { id, holder: "Test holder", issuer: "Test issuer", validUntil: "2099-01-01T00:00:00Z" };
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
      entered();
      return new Promise(resolve => { answer = resolve; });
    } },
    runHelper: async (_binary, header) => { assert.equal(header.action, "list"); return { certificates: [cert] }; },
  });
  const result = handlers.get("folio:certificates-sign")({ sender }, input());
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
