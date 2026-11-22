const { prepareCertificatePdf } = require("./certificate-pdf.cjs");
const port = process.parentPort;
const send = value => port ? port.postMessage(value) : process.send(value);
let prepared;
async function receive(message) {
  try {
    if (!prepared && message.pdf instanceof Uint8Array) {
      prepared = await prepareCertificatePdf(message.pdf, message.appearance);
      send({ covered: prepared.toSign });
    } else if (prepared && message.cms instanceof Uint8Array) {
      send({ bytes: prepared.finish(Buffer.from(message.cms)) });
    } else send({ error: "pdf_signature_failed" });
  } catch (error) { send({ error: error?.code || "pdf_signature_failed" }); }
}
if (port) port.on("message", ({ data }) => void receive(data));
else process.on("message", message => void receive(message));
