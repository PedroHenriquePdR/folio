// Use the offset at the instant of signing, even if the PDF worker is in a different time zone.
export function stampLines(holder, taxId, signedAt, utcOffsetMinutes) {
  const local = new Date(Date.parse(signedAt) + utcOffsetMinutes * 60_000).toISOString();
  const [year, month, day] = local.slice(0, 10).split("-");
  const offset = Math.abs(utcOffsetMinutes);
  const hours = String(Math.floor(offset / 60)).padStart(2, "0");
  const minutes = String(offset % 60).padStart(2, "0");
  const zone = `UTC${utcOffsetMinutes < 0 ? "-" : "+"}${hours}:${minutes}`;
  return [
    "Assinado digitalmente", holder,
    ...(taxId ? [`${taxId.type}: ${taxId.value}`] : []),
    `${day}/${month}/${year} ${local.slice(11, 19)} ${zone}`, "ICP-Brasil",
  ];
}
