import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { PDFDocument } from "pdf-lib";
import { PDF } from "@libpdf/core";
import { stampLayout, stampSize } from "../electron/certificate-layout.mjs";

export async function checkCertificateSigning(app, page, profile) {
  const file = path.join(profile, "signed-copy.pdf");
  // Exercise the normal desktop bridge and PDF utility process with two invented identities. No personal store is opened.
  await app.evaluate(({ app, ipcMain, session, BrowserWindow }, file) => {
    const require = process.getBuiltinModule("node:module").createRequire(app.getAppPath() + "/package.json");
    const { registerCertificateSigning } = require("./electron/certificate-signing.cjs");
    const state = globalThis.folioCertificateSmoke = { choices: [], signed: [], approve: false };
    const certs = ["First", "Affonso Affonso Comercio Santos"].map((holder, i) => ({ id: (i ? "ab" : "cd").repeat(32), holder,
      stampName: holder, ...(i ? { taxId: { type: "CPF", value: "123.456.789-09" } } : {}), issuer: "Folio Test CA", validUntil: "2099-06-01T12:00:00Z" }));
    for (const method of ["list", "sign", "cancel"]) ipcMain.removeHandler("folio:certificates-" + method);
    registerCertificateSigning((channel, listener) => ipcMain.handle(channel, listener), () => BrowserWindow.getAllWindows()[0], {
      app,
      runHelper: async (_binary, header) => {
        if (header.action === "list") return { certificates: certs };
        state.signed.push(header.id);
        return { cms: "MAMCAQE=" };
      },
      dialog: { showMessageBox: async (_parent, options) => {
        state.choices.push(options.detail);
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
  const choose = dialog.getByRole("radio", { name: /Affonso Affonso Comercio Santos.*Folio Test CA.*2099/ });
  await dialog.waitFor();
  try { await choose.waitFor({ timeout: 7000 }); }
  catch (error) { throw new Error("Certificate dialog: " + await dialog.innerText(), { cause: error }); }
  const sign = dialog.getByRole("button", { name: "Sign copy" });
  assert.equal(await sign.isEnabled(), false);
  await choose.check();
  assert.equal(await dialog.getByRole("checkbox", { name: "Add a visible stamp" }).isChecked(), true);
  await dialog.getByRole("img", { name: /CPF: 123\.456\.789-09/ }).waitFor();
  await page.evaluate(async () => { await document.fonts.load("1000px FolioArabic"); });
  // At 13 points this name is just over the PDF's 216-point line width. Compare
  // the final fitted rows with the embedded font, including the size after wrapping.
  const labels = await dialog.locator(".certificate-sample svg text").allTextContents();
  const date = labels.find(text => / UTC[+-]\d\d:\d\d$/.test(text));
  assert.ok(date);
  const font = (await PDF.create()).embedFont(readFileSync(new URL(import.meta.resolve("dejavu-fonts-ttf/ttf/DejaVuSans.ttf"))));
  const expected = stampLayout(["Assinado digitalmente", "Affonso Affonso Comercio Santos", "CPF: 123.456.789-09", date, "ICP-Brasil"],
    stampSize.width, stampSize.height, (text, size) => font.widthOfTextAtSize(text, size));
  await page.waitForFunction(expectedRows => {
    const rows = [...document.querySelectorAll(".certificate-sample svg text")];
    return rows.length === expectedRows.length && rows.every((el, i) => el.textContent === expectedRows[i].text &&
      Math.abs(Number(el.getAttribute("font-size")) - expectedRows[i].size) < 0.001 &&
      Math.abs(Number(el.getAttribute("y")) - expectedRows[i].baseline) < 0.001);
  }, expected.rows, { polling: 50, timeout: 5000 });
  assert.equal(await sign.isEnabled(), false);
  await dialog.getByRole("button", { name: "Place stamp on page 1" }).press("Enter");
  assert.equal(await sign.isEnabled(), true);
  await dialog.getByRole("spinbutton", { name: "Stamp page" }).fill("2");
  assert.equal(await sign.isEnabled(), false);
  const paper = dialog.getByRole("button", { name: "Place stamp on page 2" });
  await paper.waitFor();
  assert.ok(await paper.locator("canvas").evaluate(canvas => {
    const pixels = canvas.getContext("2d").getImageData(0, 0, canvas.width, canvas.height).data;
    return pixels.some((value, index) => index % 4 === 0 && value < 180);
  }), "the page preview contains document ink");
  await paper.click({ position: { x: 4, y: 4 } });
  await dialog.getByRole("slider", { name: "Stamp width" }).press("Home");
  await paper.press("ArrowRight");
  await sign.click();
  await page.waitForFunction(() => !document.querySelector('.certificate-form button[type="submit"]')?.disabled);
  assert.deepEqual(await app.evaluate(() => globalThis.folioCertificateSmoke.signed), []);
  assert.equal(existsSync(file), false);
  await app.evaluate(() => { globalThis.folioCertificateSmoke.approve = true; });
  await sign.click();
  await dialog.waitFor({ state: "hidden", timeout: 20_000 });
  const download = await app.evaluate(() => globalThis.folioCertificateSmoke.download);
  assert.equal(download.status, "completed");
  assert.match(download.name, / \(signed\)\.pdf$/);
  const approvals = await app.evaluate(() => globalThis.folioCertificateSmoke.choices);
  assert.equal(approvals.length, 2);
  for (const detail of approvals) {
    assert.match(detail, /^Holder: Affonso Affonso Comercio Santos\n/);
    assert.match(detail, /Visible signature on page 2\nCPF: 123\.456\.789-09/);
  }
  assert.deepEqual(await app.evaluate(() => globalThis.folioCertificateSmoke.signed), ["ab".repeat(32)]);
  const saved = await PDFDocument.load(readFileSync(file));
  const field = saved.getForm().getFields().find(field => field.constructor.name === "PDFSignature");
  assert.ok(field);
  const [widget] = field.acroField.getWidgets();
  assert.equal(widget.P().toString(), saved.getPage(1).ref.toString());
  assert.deepEqual(widget.getRectangle(), { x: 55, y: 724, width: 130, height: 54 });
  assert.ok(widget.getAppearances().normal.getContents().length > 0);
  console.log("ok  selected certificate, cancelled approval and visible signature at the chosen position on page 2");
}
