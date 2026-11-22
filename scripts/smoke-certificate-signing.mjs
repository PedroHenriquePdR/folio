import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { PDFDocument } from "pdf-lib";

export async function checkCertificateSigning(app, page, profile) {
  const file = path.join(profile, "signed-copy.pdf");
  // Exercise the normal desktop bridge and PDF utility process with two invented identities. No personal store is opened.
  await app.evaluate(({ app, ipcMain, session, BrowserWindow }, file) => {
    const require = process.getBuiltinModule("node:module").createRequire(app.getAppPath() + "/package.json");
    const { registerCertificateSigning } = require("./electron/certificate-signing.cjs");
    const state = globalThis.folioCertificateSmoke = { choices: [], signed: [], approve: false };
    const certs = ["First", "Second"].map((holder, i) => ({ id: (i ? "ab" : "cd").repeat(32), holder,
      issuer: "Folio Test CA", validUntil: "2099-06-01T12:00:00Z" }));
    for (const method of ["list", "sign", "cancel"]) ipcMain.removeHandler("folio:certificates-" + method);
    registerCertificateSigning((channel, listener) => ipcMain.handle(channel, listener), () => BrowserWindow.getAllWindows()[0], {
      app,
      runHelper: async (_binary, header) => {
        if (header.action === "list") return { certificates: certs };
        state.signed.push(header.id);
        return { cms: "MAMCAQE=" };
      },
      dialog: { showMessageBox: async (_parent, options) => {
        state.choices.push(options.detail.split("\n")[0]);
        return { response: state.approve ? 1 : 0 };
      } },
    });
    state.download = new Promise(resolve => session.defaultSession.once("will-download", (_event, item) => {
      const name = item.getFilename();
      item.setSavePath(file);
      item.once("done", (_done, status) => resolve({ name, status }));
    }));
  }, file);
  await page.getByRole("button", { name: "More", exact: true }).click();
  await page.getByRole("menuitem", { name: "Sign with a certificate" }).click();
  const dialog = page.getByRole("dialog", { name: "Sign with a certificate" });
  const choose = dialog.getByRole("radio", { name: /Second.*Folio Test CA.*2099/ });
  await dialog.waitFor();
  try { await choose.waitFor({ timeout: 7000 }); }
  catch (error) { throw new Error("Certificate dialog: " + await dialog.innerText(), { cause: error }); }
  const sign = dialog.getByRole("button", { name: "Sign copy" });
  assert.equal(await sign.isEnabled(), false);
  await choose.check();
  await sign.click();
  await page.waitForFunction(() => !document.querySelector('.certificate-form button[type="submit"]')?.disabled);
  assert.deepEqual(await app.evaluate(() => globalThis.folioCertificateSmoke.signed), []);
  await app.evaluate(() => { globalThis.folioCertificateSmoke.approve = true; });
  await sign.click();
  await dialog.waitFor({ state: "hidden", timeout: 20_000 });
  const download = await app.evaluate(() => globalThis.folioCertificateSmoke.download);
  assert.equal(download.status, "completed");
  assert.match(download.name, / \(signed\)\.pdf$/);
  assert.deepEqual(await app.evaluate(() => globalThis.folioCertificateSmoke.choices), ["Holder: Second", "Holder: Second"]);
  assert.deepEqual(await app.evaluate(() => globalThis.folioCertificateSmoke.signed), ["ab".repeat(32)]);
  const saved = await PDFDocument.load(readFileSync(file));
  assert.ok(saved.getForm().getFields().some(field => field.constructor.name === "PDFSignature"));
  console.log("ok  selected certificate, cancelled approval and signed PDF download");
}
