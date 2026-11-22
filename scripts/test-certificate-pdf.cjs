const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { test } = require("node:test");
const {
  PDFArray, PDFDict, PDFDocument, PDFHexString, PDFName, PDFNumber, PDFRef, PDFString,
} = require("pdf-lib");
const { prepareCertificatePdf } = require("../electron/certificate-pdf.cjs");

const name = PDFName.of;
const cms = Buffer.from("30050203010203", "hex");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function documentBytes(edit, useObjectStreams = false) {
  const doc = await PDFDocument.create();
  const page = doc.addPage([200, 400]);
  await edit?.(doc, page);
  return Buffer.from(await doc.save({ useObjectStreams, updateFieldAppearances: false }));
}

function fieldObjects(doc) {
  const form = doc.catalog.lookup(name("AcroForm"), PDFDict);
  const fields = form.lookup(name("Fields"), PDFArray).asArray();
  return fields.map((ref) => ({ ref, field: doc.context.lookup(ref, PDFDict) }));
}

for (const useObjectStreams of [false, true]) {
  test(`signing covers the exact PDF and preserves forms and annotations (object streams: ${useObjectStreams})`, async () => {
    const original = await documentBytes((doc, page) => {
      const text = doc.getForm().createTextField("Customer");
      text.setText("Fictional customer");
      text.addToPage(page, { x: 0, y: 0, width: 80, height: 20 });
      // Rewriting a later object must never redirect the exclusion into a string from the input.
      page.node.set(name("FolioTest"), PDFString.of("/ByteRange [0 0 0 0] /Contents <DECAFBAD>"));
      const form = doc.catalog.lookup(name("AcroForm"), PDFDict);
      form.set(name("Fields"), doc.context.register(form.lookup(name("Fields"), PDFArray)));
      page.node.set(name("Annots"), doc.context.register(page.node.lookup(name("Annots"), PDFArray)));
    }, useObjectStreams);
    const copy = Buffer.from(original);
    const staged = await prepareCertificatePdf(original);
    const output = staged.finish(cms);
    assert.ok(Buffer.isBuffer(staged.toSign));
    assert.ok(Buffer.isBuffer(output));
    assert.deepEqual(original, copy);
    assert.ok(output.length > original.length, "the signature is an incremental revision");
    assert.deepEqual(output.subarray(0, original.length), original);

    // pdf-lib independently resolves the actual field dictionary, including the object-stream case.
    const parsed = await PDFDocument.load(output, { updateMetadata: false });
    assert.equal(parsed.getForm().getTextField("Customer").getText(), "Fictional customer");
    const fields = fieldObjects(parsed);
    assert.equal(fields.length, 2);
    const { ref, field } = fields.find(({ field }) => field.get(name("FT")) === name("Sig"));
    const page = parsed.getPages()[0];
    assert.deepEqual(page.getSize(), { width: 200, height: 400 });
    assert.equal(page.node.lookup(name("FolioTest"), PDFString).decodeText(), "/ByteRange [0 0 0 0] /Contents <DECAFBAD>");
    assert.equal(page.node.lookup(name("Annots"), PDFArray).size(), 2);
    assert.ok(page.node.lookup(name("Annots"), PDFArray).asArray().includes(ref));
    assert.equal(field.get(name("P")), page.ref);
    const sig = field.lookup(name("V"), PDFDict);
    assert.equal(sig.get(name("Type")), name("Sig"));
    assert.equal(sig.get(name("Filter")), name("PBAD_PAdES"));
    assert.equal(sig.get(name("SubFilter")), name("PBAD.PAdES"));
    const range = sig.lookup(name("ByteRange"), PDFArray).asArray().map((n) => n.asNumber());
    const [zero, start, end, remaining] = range;
    assert.equal(range.length, 4);
    assert.equal(zero, 0);
    assert.ok(start > original.length);
    assert.equal(end + remaining, output.length);
    const contents = sig.lookup(name("Contents"), PDFHexString);
    assert.equal(output.toString("ascii", start, end).toLowerCase(), `<${contents.asString().toLowerCase()}>`);
    assert.deepEqual(Buffer.from(contents.asBytes().subarray(0, cms.length)), cms);
    assert.ok(contents.asBytes().subarray(cms.length).every((n) => n === 0));
    const signedBytes = (pdf) => Buffer.concat([pdf.subarray(0, start), pdf.subarray(end)]);
    assert.deepEqual(signedBytes(output), staged.toSign);
    const tampered = Buffer.from(output);
    tampered[6] ^= 1;
    assert.notEqual(digest(signedBytes(tampered)), digest(staged.toSign));
    assert.deepEqual(signedBytes(staged.finish(Buffer.from([0x30, 0]))), staged.toSign);

    const refEntry = sig.lookup(name("Reference"), PDFArray).get(0);
    assert.ok(refEntry instanceof PDFRef);
    const mdp = parsed.context.lookup(refEntry, PDFDict);
    assert.equal(mdp.get(name("TransformMethod")), name("DocMDP"));
    assert.ok(mdp.get(name("TransformParams")) instanceof PDFRef);
    const params = mdp.lookup(name("TransformParams"), PDFDict);
    assert.equal(params.lookup(name("P"), PDFNumber).asNumber(), 2);
    assert.equal(params.get(name("V")), name("1.2"));
    assert.equal(parsed.catalog.has(name("Perms")), false);
    const esic = parsed.catalog.lookup(name("Extensions"), PDFDict).lookup(name("ESIC"), PDFDict);
    assert.equal(esic.get(name("BaseVersion")), name("1.7"));
    assert.equal(esic.lookup(name("ExtensionLevel"), PDFNumber).asNumber(), 2);
  });
}

test("the copy retains registered extensions and upgrades an older PDF through its catalog", async () => {
  const original = await documentBytes((doc) => {
    doc.catalog.set(name("Extensions"), doc.context.register(doc.context.obj({
      ADBE: { BaseVersion: "1.7", ExtensionLevel: 8 },
      ESIC: doc.context.register(doc.context.obj({ BaseVersion: "1.7", ExtensionLevel: 5 })),
    })));
  });
  original.write("1.4", 5, "ascii");
  const signed = (await prepareCertificatePdf(original)).finish(cms);
  assert.deepEqual(signed.subarray(0, original.length), original);
  const { catalog } = await PDFDocument.load(signed);
  assert.equal(catalog.get(name("Version")), name("1.7"));
  const extensions = catalog.lookup(name("Extensions"), PDFDict);
  assert.equal(extensions.lookup(name("ADBE"), PDFDict).lookup(name("ExtensionLevel")).asNumber(), 8);
  assert.equal(extensions.lookup(name("ESIC"), PDFDict).lookup(name("ExtensionLevel")).asNumber(), 5);
});

function existingField(doc, page, properties = {}) {
  const widget = doc.context.register(doc.context.obj({
    Type: "Annot", Subtype: "Widget", FT: "Sig", T: PDFString.of("ICP-Brasil"),
    Rect: [10, 20, 90, 40], P: page.ref, ...properties,
  }));
  page.node.set(name("Annots"), doc.context.obj([widget]));
  doc.catalog.set(name("AcroForm"), doc.context.obj({ Fields: [widget], SigFlags: 1 }));
}

test("a new field leaves a preallocated blank signature widget available for its intended signer", async () => {
  const original = await documentBytes((doc, page) => existingField(doc, page));
  const parsed = await PDFDocument.load((await prepareCertificatePdf(original)).finish(cms));
  const [blank, signed] = fieldObjects(parsed);
  assert.equal(blank.field.has(name("V")), false);
  assert.equal(blank.field.lookup(name("T")).decodeText(), "ICP-Brasil");
  assert.deepEqual(blank.field.lookup(name("Rect")).asArray().map((n) => n.asNumber()), [10, 20, 90, 40]);
  assert.notEqual(blank.field.lookup(name("T")).decodeText(), signed.field.lookup(name("T")).decodeText());
  assert.equal(signed.field.lookup(name("V")).get(name("Type")), name("Sig"));
});

test("a nested signature value is found even after an empty signature field", async () => {
  const original = await documentBytes((doc, page) => {
    existingField(doc, page);
    const value = doc.context.register(doc.context.obj({ ByteRange: [0, 1, 3, 4], Contents: PDFHexString.of("30") }));
    const child = doc.context.register(doc.context.obj({ T: PDFString.of("Child"), V: value }));
    const parent = doc.context.register(doc.context.obj({ FT: "Sig", T: PDFString.of("Group"), Kids: [child] }));
    doc.context.lookup(child).set(name("Parent"), parent);
    doc.catalog.lookup(name("AcroForm")).lookup(name("Fields")).push(parent);
  }, true);
  const copy = Buffer.from(original);
  await assert.rejects(prepareCertificatePdf(original), /already signed|assinad[oa]/i);
  assert.deepEqual(original, copy);
});

for (const key of ["SV", "Lock"]) {
  test(`a signature field with /${key} constraints cannot be bypassed by adding another field`, async () => {
    const input = await documentBytes((doc, page) => existingField(doc, page, { [key]: {} }));
    await assert.rejects(prepareCertificatePdf(input), /restri|constraint/i);
  });
}

test("an existing certification is detected without a signature field", async () => {
  const bytes = await documentBytes((doc) => {
    doc.catalog.set(name("Perms"), doc.context.obj({ DocMDP: doc.context.register(doc.context.obj({ Type: "Sig" })) }));
  });
  await assert.rejects(prepareCertificatePdf(bytes), /certific|already signed/i);
});

test("encrypted and unparseable PDFs have actionable errors", async () => {
  const { PDF } = await import("@libpdf/core");
  const doc = await PDF.load(await documentBytes());
  doc.setProtection({ algorithm: "AES-256", ownerPassword: "invented", userPassword: "" });
  await assert.rejects(prepareCertificatePdf(await doc.save()), /encrypted|protected|criptografad|protegid/i);
  await assert.rejects(prepareCertificatePdf(Buffer.from("%PDF-1.7\nmalformed")), /invalid|damaged|unsupported|inválid|incompatível/i);
});

test("XFA forms and broken field references are refused instead of being replaced", async () => {
  const xfa = await documentBytes((doc) => doc.catalog.set(name("AcroForm"), doc.context.obj({ Fields: [], XFA: [] })));
  await assert.rejects(prepareCertificatePdf(xfa), /XFA/);
  const broken = await documentBytes((doc) => doc.catalog.set(name("AcroForm"), doc.context.obj({ Fields: PDFRef.of(900, 0) })));
  await assert.rejects(prepareCertificatePdf(broken), /malformed|invalid|unsupported|inválid|incompatível/i);
});

test("finish rejects empty and oversized CMS values without truncating them", async () => {
  const staged = await prepareCertificatePdf(await documentBytes());
  assert.throws(() => staged.finish(Buffer.alloc(0)), /CMS|signature|assinatura/i);
  assert.throws(() => staged.finish(Buffer.alloc(32769)), /CMS|signature|assinatura/i);
  const full = Buffer.alloc(32768, 0xab);
  const parsed = await PDFDocument.load(staged.finish(full));
  const stored = fieldObjects(parsed)[0].field.lookup(name("V")).lookup(name("Contents")).asBytes();
  assert.deepEqual(Buffer.from(stored), full);
});

test("archival metadata recognizes PDF/A-1 in both RDF forms and leaves PDF/A-2 metadata intact", async () => {
  for (const [part, rdf] of [
    [1, '<rdf:Description a:part="1"/>'],
    [1, '<rdf:Description><a:part>1</a:part></rdf:Description>'],
    [2, '<rdf:Description a:part="2"/>'],
  ]) {
    const xml = `<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:a="http://www.aiim.org/pdfa/ns/id/">${rdf}</rdf:RDF>`;
    const original = await documentBytes((doc) => {
      doc.catalog.set(name("Metadata"), doc.context.register(doc.context.stream(xml, { Type: "Metadata", Subtype: "XML" })));
    });
    if (part === 1) await assert.rejects(prepareCertificatePdf(original), { code: "pdf_a1" });
    else {
      const parsed = await PDFDocument.load((await prepareCertificatePdf(original)).finish(cms));
      assert.equal(Buffer.from(parsed.catalog.lookup(name("Metadata")).getContents()).toString("utf8"), xml);
    }
  }
});

test("unsigned revisions can be signed but removing a signed field in a later revision cannot hide it", async () => {
  const { PDF, PdfArray, PdfName } = await import("@libpdf/core");
  const original = await documentBytes();
  const doc = await PDF.load(original);
  doc.getCatalog().set("PageLayout", PdfName.of("OneColumn"));
  const updated = await doc.save({ incremental: true });
  const signed = (await prepareCertificatePdf(updated)).finish(cms);
  assert.deepEqual(signed.subarray(0, updated.length), Buffer.from(updated));
  const edited = await PDF.load(signed);
  const resolve = (ref) => edited.getObject(ref);
  edited.getCatalog().getDict("AcroForm", resolve).set("Fields", new PdfArray());
  edited.getPage(0).dict.set("Annots", new PdfArray());
  const noVisibleFields = await edited.save({ incremental: true });
  const independent = await PDFDocument.load(noVisibleFields);
  assert.deepEqual(fieldObjects(independent), []);
  await assert.rejects(prepareCertificatePdf(noVisibleFields), { code: "pdf_already_signed" });
});
