// Linux uses a private NSS database. The other backends are exercised only on disposable GitHub-hosted runners.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { X509Certificate } = require("node:crypto");
const { execFileSync, spawnSync } = require("node:child_process");
const { PDFDocument, PDFName, PDFDict, PDFArray, PDFHexString, PDFRawStream, degrees } = require("pdf-lib");
const { createCertificateService, runCertificateHelper } = require("../electron/certificate-signing.cjs");

const linux = process.platform === "linux";
const hostedRequested = process.env.FOLIO_TEST_SIGNING_IDENTITY === "1";
if (!linux && hostedRequested) assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted", "generated identities require a disposable runner");

test("an imported software A1 signs PDF byte ranges that OpenSSL verifies independently", { skip: !linux && !hostedRequested }, async () => {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "folio-test-signature-"));
  const xdg = path.join(profile, "share"), db = path.join(xdg, "pki", "nssdb");
  if (linux) fs.mkdirSync(db, { mode: 0o700, recursive: true });
  const file = name => path.join(profile, name);
  const secret = "folio-local-test";
  fs.writeFileSync(file("password"), secret + "\n", { mode: 0o600 });
  const env = linux ? { ...process.env, HOME: profile, XDG_DATA_HOME: xdg } : process.env;
  const binary = path.resolve(__dirname, "..", "native-bin", process.platform === "win32" ? "folio-certsign.exe" : "folio-certsign");
  const run = (tool, args) => execFileSync(tool, args, { cwd: profile, env, stdio: "pipe" });
  run("openssl", ["req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=Folio A1 Test",
    "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature,nonRepudiation",
    "-addext", "subjectAltName=otherName:2.16.76.1.3.1;OCTETSTRING:010119901234567890900000000000000000000000000000000",
    "-addext", "certificatePolicies=2.16.76.1.2.1.99", "-keyout", "test.key", "-out", "test.pem"]);
  const pkcs12 = ["pkcs12", "-export", "-out", "test.p12", "-inkey", "test.key", "-in", "test.pem", "-passout", "file:password"];
  // Apple's legacy PKCS#12 importer expects this encoding of the disposable test credential.
  if (process.platform === "darwin") pkcs12.push("-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1");
  run("openssl", pkcs12);
  if (linux) {
    run("certutil", ["-N", "-d", "sql:" + db, "-f", file("password")]);
    run("pk12util", ["-i", file("test.p12"), "-d", "sql:" + db, "-k", file("password"), "-w", file("password")]);
  } else if (process.platform === "win32") {
    run("certutil.exe", ["-user", "-f", "-p", secret, "-importPFX", "My", file("test.p12"), "NoRoot"]);
  } else {
    const chain = file("folio-test.keychain-db");
    const existing = [...run("security", ["list-keychains", "-d", "user"]).toString().matchAll(/"([^"]+)"/g)].map(match => match[1]);
    run("security", ["create-keychain", "-p", secret, chain]);
    run("security", ["unlock-keychain", "-p", secret, chain]);
    run("security", ["list-keychains", "-d", "user", "-s", chain, ...existing]);
    run("security", ["import", file("test.p12"), "-k", chain, "-P", secret, "-T", binary]);
  }

  const service = createCertificateService({
    run: (header, payload, signal) => runCertificateHelper(binary, header, payload, signal, env),
    confirm: async (name, cert) => name === "test.pdf" && cert.holder === "Folio A1 Test",
  });
  if (linux) assert.deepEqual(await service.list("incorrect"), { error: "password_required" });
  const result = await service.list(secret);
  assert.equal(result.error, undefined);
  if (linux) assert.equal(result.certificates.length, 1);
  const certificate = new X509Certificate(fs.readFileSync(file("test.pem")));
  const id = certificate.fingerprint256.replaceAll(":", "").toLowerCase();
  const identity = result.certificates.find(cert => cert.id === id);
  assert.equal(identity?.stampName, "Folio A1 Test");
  assert.deepEqual(identity.taxId, { type: "CPF", value: "123.456.789-09" });

  const source = await PDFDocument.create();
  source.addPage([100, 150]).drawText("Folio test");
  const page = source.addPage([420, 520]);
  page.setCropBox(20, 40, 380, 440);
  page.setRotation(degrees(90));
  const original = Buffer.from(await source.save());
  const placement = { pageNumber: 2, rect: [90, 110, 172, 340] };
  const request = { requestId: "nss-e2e", id, name: "test.pdf", password: secret, data: original, placement };
  const signed = await service.sign(request);
  assert.ok(signed.bytes, JSON.stringify({ error: signed.error, cancelled: signed.cancelled }));
  const output = Buffer.from(signed.bytes);
  assert.deepEqual(output.subarray(0, original.length), original);
  const pdf = await PDFDocument.load(output);
  const key = PDFName.of;
  assert.equal(pdf.getForm().getFields().length, 1);
  const [field] = pdf.getForm().getFields();
  assert.equal(field.acroField.dict.get(key("P")).toString(), pdf.getPages()[1].ref.toString());
  assert.deepEqual(field.acroField.dict.lookup(key("Rect"), PDFArray).asArray().map(n => n.asNumber()), placement.rect);
  const normal = field.acroField.dict.lookup(key("AP"), PDFDict).lookup(key("N"), PDFRawStream);
  const sig = field.acroField.dict.lookup(key("V"), PDFDict);
  const range = sig.lookup(key("ByteRange"), PDFArray).asArray().map(n => n.asNumber());
  assert.equal(range[0], 0);
  assert.equal(range[2] + range[3], output.length);
  assert.equal(output[range[1]], 0x3c);
  assert.equal(output[range[2] - 1], 0x3e);
  const covered = Buffer.concat([output.subarray(0, range[1]), output.subarray(range[2])]);
  const padded = Buffer.from(sig.lookup(key("Contents"), PDFHexString).asBytes());
  assert.equal(padded[0], 0x30);
  const lengthBytes = padded[1] & 0x7f;
  assert.ok((padded[1] & 0x80) && lengthBytes > 0 && lengthBytes <= 3);
  const size = 2 + lengthBytes + padded.readUIntBE(2, lengthBytes);
  assert.ok(padded.subarray(size).every(b => b === 0));
  fs.writeFileSync(file("cms.der"), padded.subarray(0, size));
  fs.writeFileSync(file("covered.pdf"), covered);
  const args = ["cms", "-verify", "-binary", "-inform", "DER", "-in", "cms.der", "-content", "covered.pdf",
    "-nointern", "-certfile", "test.pem", "-noverify", "-out", os.devNull];
  run("openssl", args);
  // Change a byte inside the actual widget appearance, after locating its serialized stream independently.
  const streamBytes = Buffer.from(normal.getContents());
  assert.ok(streamBytes.length > 8);
  const appearanceOffset = covered.indexOf(streamBytes);
  assert.ok(appearanceOffset >= original.length);
  assert.equal(covered.indexOf(streamBytes, appearanceOffset + 1), -1);
  covered[appearanceOffset + Math.floor(streamBytes.length / 2)] ^= 1;
  fs.writeFileSync(file("covered.pdf"), covered);
  const tampered = spawnSync("openssl", args, { cwd: profile, env, encoding: "utf8" });
  assert.notEqual(tampered.status, 0);
  assert.match(tampered.stderr, /verification failure|verification error/i);
  assert.deepEqual(await service.sign({ ...request, data: output }), { error: "pdf_already_signed" });

  const hidden = await service.sign({ ...request, placement: undefined });
  assert.ok(hidden.bytes, JSON.stringify({ error: hidden.error, cancelled: hidden.cancelled }));
  const withoutMark = await PDFDocument.load(hidden.bytes);
  const [hiddenField] = withoutMark.getForm().getFields();
  assert.equal(hiddenField.constructor.name, "PDFSignature");
  assert.deepEqual(hiddenField.acroField.dict.lookup(key("Rect"), PDFArray).asArray().map(n => n.asNumber()), [0, 0, 0, 0]);
  assert.equal(hiddenField.acroField.dict.has(key("AP")), false);
});
