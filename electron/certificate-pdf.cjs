const CMS_BYTES = 32 * 1024;
const PDF_HEADER = Buffer.from("%PDF-");
const EMPTY_RANGE = "[0 0000000000 0000000000 0000000000]";
const EMPTY_CONTENTS = `<${"0".repeat(CMS_BYTES * 2)}>`;

const messages = {
  pdf_invalid: "This PDF is damaged or has an invalid document structure.",
  pdf_encrypted: "Encrypted PDFs cannot be signed in Folio.",
  pdf_already_signed: "This PDF is already signed or certified. Choose an unsigned PDF.",
  pdf_restricted_field: "This form contains a signature field with signing restrictions.",
  pdf_xfa: "Folio cannot sign XFA forms.",
  pdf_a1: "PDF/A-1 does not support this signature. Choose a PDF/A-2 or later copy.",
  pdf_unsupported: "Folio cannot add a first signature to this PDF format.",
  pdf_signature_failed: "Folio could not prepare the PDF signature.",
  invalid_placement: "Choose a position and size that fit the page.",
  stamp_glyph: "This font cannot display the holder's name. Turn off the visible stamp to sign.",
  cms_size: "The CMS signature is empty or exceeds 32 KiB.",
};

function fail(code) {
  throw Object.assign(new Error(messages[code]), { code });
}

function resolveValue(raw, resolve) {
  if (raw?.type !== "ref") return raw;
  return resolve(raw) ?? fail("pdf_invalid");
}

function entry(dict, key, type, resolve) {
  const value = resolveValue(dict.get(key), resolve);
  if (!value || value.type === "null") return undefined;
  if (type && value.type !== type) fail("pdf_invalid");
  return value;
}

// Fields can inherit /FT from an ancestor. Visit the entire tree before deciding whether
// another field can be added, including widgets stored separately from their field.
function inspectFields(fields, pages, resolve, current) {
  const names = new Set();
  const visited = new Set();
  const pending = [];
  for (const field of fields) pending.push({ field });
  while (pending.length) {
    const { field, parentType } = pending.pop();
    const dict = resolveValue(field, resolve);
    if (dict?.type !== "dict" || visited.has(dict)) fail("pdf_invalid");
    visited.add(dict);
    const type = entry(dict, "FT", "name", resolve)?.value ?? parentType;
    const value = entry(dict, "V", undefined, resolve);
    if ((type === "Sig" && value) || (value?.type === "dict"
      && (value.has("ByteRange") || ["Sig", "DocTimeStamp"].includes(value.getName("Type")?.value)))) {
      fail("pdf_already_signed");
    }
    if (current && (dict.has("SV") || dict.has("Lock"))) fail("pdf_restricted_field");
    const name = entry(dict, "T", "string", resolve);
    if (name) names.add(name.asString());
    const kids = entry(dict, "Kids", "array", resolve);
    if (kids) for (const kid of kids) pending.push({ field: kid, parentType: type });
  }
  for (const page of pages) {
    const annots = entry(page.dict, "Annots", "array", resolve);
    if (!annots) continue;
    for (const ref of annots) {
      const annot = resolveValue(ref, resolve);
      if (annot?.type !== "dict") fail("pdf_invalid");
      if (!visited.has(annot) && (annot.getName("Subtype")?.value === "Widget" || annot.has("FT"))) {
        fail("pdf_invalid");
      }
    }
  }
  let name = "ICP-Brasil";
  for (let i = 2; names.has(name); i++) name = `ICP-Brasil ${i}`;
  return name;
}

function unsignedForm(pdf, current) {
  if (pdf.isEncrypted || pdf.context.info.trailer.has("Encrypt")) fail("pdf_encrypted");
  const resolve = (ref) => pdf.getObject(ref);
  const catalog = pdf.getCatalog();
  const permissions = entry(catalog, "Perms", "dict", resolve);
  if (permissions && ["DocMDP", "UR", "UR3"].some((key) => permissions.has(key))) fail("pdf_already_signed");
  if (permissions?.size || entry(catalog, "DSS", "dict", resolve)) fail("pdf_unsupported");
  const pages = pdf.getPages();
  if (!pages.length) fail("pdf_invalid");
  const form = entry(catalog, "AcroForm", "dict", resolve);
  if (form?.has("XFA")) fail("pdf_xfa");
  const fields = form && entry(form, "Fields", "array", resolve);
  if (form && !fields) fail("pdf_invalid");
  const fieldName = inspectFields(fields ?? [], pages, resolve, current);
  return { resolve, catalog, pages, form, fields, fieldName };
}

function startXref(bytes) {
  let end = bytes.length;
  while (end && [0, 9, 10, 12, 13, 32].includes(bytes[end - 1])) end--;
  const tail = bytes.toString("latin1", Math.max(0, end - 1024), end);
  const marker = /[\r\n]startxref[\x00\t\n\f\r ]+(\d+)[\x00\t\n\f\r ]+%%EOF$/.exec(tail);
  const offset = marker && Number(marker[1]);
  if (!Number.isSafeInteger(offset) || offset < 1 || offset >= end) fail("pdf_invalid");
  return offset;
}

// In a linearized file, the first-page trailer points *forward* to another xref in
// the same revision (ISO 32000-1, Annex F). The first indirect object identifies it.
function isLinearizedRevision(pdf, bytes, currentOffset, PdfRef) {
  const first = /^%PDF-[^\r\n]*[\r\n]\s*(?:%[^\r\n]*[\r\n]\s*)*(\d+)\s+(\d+)\s+obj\b/
    .exec(bytes.toString("latin1", 0, 1024));
  if (!first) return false;
  const params = pdf.getObject(PdfRef.of(Number(first[1]), Number(first[2])));
  if (params?.type !== "dict" || params.getNumber("Linearized")?.value !== 1) return false;
  const length = params.getNumber("L")?.value;
  return Number.isSafeInteger(length) && length > currentOffset && length <= bytes.length
    && params.has("H") && params.has("T") && params.has("O") && params.has("N")
    && startXref(bytes.subarray(0, length)) === currentOffset;
}

async function checkHistory(pdf, source, storage, PDF, PdfRef) {
  let currentOffset = startXref(source);
  let trailer = pdf.context.info.trailer;
  while (trailer.has("Prev")) {
    const prev = trailer.getNumber("Prev")?.value;
    if (!Number.isSafeInteger(prev) || prev < 1 || prev >= source.length) fail("pdf_invalid");
    if (prev > currentOffset && isLinearizedRevision(pdf, source, currentOffset, PdfRef)) return;
    if (prev >= currentOffset) fail("pdf_invalid");
    // Select this historical xref with our own terminal pointer, in scratch space
    // beyond the source bytes. The parser resolves the old catalog and object versions.
    const written = storage.write(`\nstartxref\n${prev}\n%%EOF\n`, source.length, "ascii");
    pdf = await PDF.load(storage.subarray(0, source.length + written), { lenient: false });
    unsignedForm(pdf, false);
    currentOffset = prev;
    trailer = pdf.context.info.trailer;
  }
}

function checkArchivalMetadata(catalog, resolve) {
  const metadata = entry(catalog, "Metadata", "stream", resolve);
  if (!metadata) return;
  const { DOMParser } = require("@xmldom/xmldom");
  const xml = new TextDecoder("utf-8", { fatal: true }).decode(metadata.getDecodedData());
  let invalid = false;
  const document = new DOMParser({ errorHandler() { invalid = true; } }).parseFromString(xml, "application/xml");
  if (invalid || !document?.documentElement) fail("pdf_invalid");
  const ns = "http://www.aiim.org/pdfa/ns/id/";
  const elements = document.getElementsByTagName("*");
  for (let i = 0; i < elements.length; i++) {
    const element = elements.item(i);
    if (Number(element.getAttributeNS(ns, "part")) === 1
      || (element.namespaceURI === ns && element.localName === "part" && Number(element.textContent) === 1)) {
      fail("pdf_a1");
    }
  }
}

// The PDF serializer supplies absolute positions as it writes our two values. Bytes
// supplied by the document are never searched for placeholder syntax.
function reserve(syntax) {
  return {
    type: "raw",
    offset: -1,
    toBytes(writer) {
      this.offset = writer.position;
      writer.writeAscii(syntax);
    },
  };
}

async function prepareCertificatePdf(bytes, appearance) {
  if (!(bytes instanceof Uint8Array) || bytes.length < PDF_HEADER.length) fail("pdf_invalid");
  const storage = Buffer.allocUnsafe(bytes.length + 64);
  const original = storage.subarray(0, bytes.length);
  original.set(bytes);
  if (!original.subarray(0, PDF_HEADER.length).equals(PDF_HEADER)) fail("pdf_invalid");
  const { PDF, PdfDict, PdfArray, PdfName, PdfNumber, PdfRef, PdfString } = await import("@libpdf/core");
  try {
    const pdf = await PDF.load(original, { lenient: false });
    const unsigned = unsignedForm(pdf, true);
    const { resolve, catalog, pages, fieldName } = unsigned;
    if (pdf.canSaveIncrementally()) fail("pdf_unsupported");
    await checkHistory(pdf, original, storage, PDF, PdfRef);
    checkArchivalMetadata(catalog, resolve);
    const mark = appearance === undefined ? undefined
      : await require("./certificate-appearance.cjs").prepareAppearance(pdf, pages, appearance, fail);
    const page = mark?.page ?? pages[0];
    const form = unsigned.form ?? new PdfDict();
    if (!unsigned.form) {
      catalog.set("AcroForm", pdf.register(form));
    }

    const priorExtensions = entry(catalog, "Extensions", "dict", resolve);
    const extensions = priorExtensions ?? new PdfDict();
    const priorEsic = entry(extensions, "ESIC", "dict", resolve);
    const esic = priorEsic ?? new PdfDict();
    const baseVersion = entry(esic, "BaseVersion", "name", resolve)?.value;
    const catalogVersion = entry(catalog, "Version", "name", resolve)?.value;
    const supportedVersion = /^(1\.[0-7]|2\.0)$/;
    if (![pdf.version, catalogVersion, baseVersion].filter(Boolean).every((v) => supportedVersion.test(v))) {
      fail("pdf_unsupported");
    }
    if (Math.max(Number(pdf.version), Number(catalogVersion ?? 0)) < 1.7) pdf.upgradeVersion("1.7");
    if (Number(baseVersion ?? 0) < 1.7) esic.set("BaseVersion", PdfName.of("1.7"));
    const level = entry(esic, "ExtensionLevel", "number", resolve)?.value ?? 0;
    if (!Number.isSafeInteger(level) || level < 0) fail("pdf_invalid");
    if (level < 2) esic.set("ExtensionLevel", PdfNumber.of(2));
    if (!priorEsic) extensions.set("ESIC", esic);
    if (!priorExtensions) catalog.set("Extensions", extensions);

    // ITI VALIDAR developer guide, chapter VI. Subsequent form filling and signing
    // are allowed. The guide recommends omitting the catalog /Perms /DocMDP entry.
    const params = pdf.register(PdfDict.of({
      Type: PdfName.of("TransformParams"), P: PdfNumber.of(2), V: PdfName.of("1.2"),
    }));
    const reference = pdf.register(PdfDict.of({
      Type: PdfName.of("SigRef"), TransformMethod: PdfName.of("DocMDP"), TransformParams: params,
    }));
    const range = reserve(EMPTY_RANGE);
    const contents = reserve(EMPTY_CONTENTS);
    const date = (appearance?.signedAt ?? new Date().toISOString()).slice(0, 19).replace(/[-:T]/g, "");
    const signature = pdf.register(PdfDict.of({
      Type: PdfName.of("Sig"), Filter: PdfName.of("PBAD_PAdES"), SubFilter: PdfName.of("PBAD.PAdES"),
      M: PdfString.fromString(`D:${date}Z`), Reference: PdfArray.of(reference), ByteRange: range, Contents: contents,
    }));
    const widget = pdf.register(PdfDict.of({
      Type: PdfName.of("Annot"), Subtype: PdfName.of("Widget"), FT: PdfName.of("Sig"),
      T: PdfString.fromString(fieldName), V: signature, P: page.ref,
      Rect: new PdfArray((mark?.rect ?? [0, 0, 0, 0]).map(PdfNumber.of)), F: PdfNumber.of(132),
      ...(mark ? { AP: PdfDict.of({ N: mark.normal }) } : {}),
    }));
    // Independent lists preserve PDFs that share an indirect array between pages or with the field tree.
    form.set("Fields", new PdfArray([...(unsigned.fields ?? []), widget]));
    const flags = entry(form, "SigFlags", "number", resolve)?.value ?? 0;
    if (!Number.isInteger(flags) || flags < 0 || flags > 0x7fffffff) fail("pdf_invalid");
    form.set("SigFlags", PdfNumber.of(flags | 3));
    const annots = entry(page.dict, "Annots", "array", resolve);
    page.dict.set("Annots", new PdfArray([...(annots ?? []), widget]));

    const saved = await pdf.save({ incremental: true, subsetFonts: true });
    const prepared = Buffer.from(saved.buffer, saved.byteOffset, saved.byteLength);
    const start = contents.offset;
    const end = start + EMPTY_CONTENTS.length;
    const actualRange = `[0 ${start} ${end} ${prepared.length - end}]`;
    if (range.offset < original.length || range.offset + EMPTY_RANGE.length > start
      || end >= prepared.length || actualRange.length > EMPTY_RANGE.length
      || !prepared.subarray(0, original.length).equals(original)
      || prepared.toString("latin1", range.offset, range.offset + EMPTY_RANGE.length) !== EMPTY_RANGE
      || prepared.toString("latin1", start, end) !== EMPTY_CONTENTS) fail("pdf_signature_failed");
    prepared.write(actualRange.padEnd(EMPTY_RANGE.length, " "), range.offset, "ascii");
    return {
      toSign: Buffer.concat([prepared.subarray(0, start), prepared.subarray(end)]),
      finish(cms) {
        if (!(cms instanceof Uint8Array) || !cms.length || cms.length > CMS_BYTES) fail("cms_size");
        const output = Buffer.from(prepared);
        output.write(Buffer.from(cms).toString("hex"), start + 1, "ascii");
        return output;
      },
    };
  } catch (error) {
    if (Object.hasOwn(messages, error?.code)) throw error;
    fail("pdf_invalid");
  }
}

module.exports = { prepareCertificatePdf };
