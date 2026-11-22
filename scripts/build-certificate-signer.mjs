import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Arch } from "electron-builder";

const root = path.resolve(import.meta.dirname, "..");
const moduleDir = path.join(root, "native", "certsign");
const binDir = path.join(root, "native-bin");

function runGo(platform, arch, args) {
  const goOS = { darwin: "darwin", linux: "linux", win32: "windows" }[platform];
  const goArch = { x64: "amd64", arm64: "arm64" }[arch];
  if (!goOS || !goArch || (platform !== "darwin" && arch !== "x64")) {
    throw new Error(`Unsupported Folio certificate signer target: ${platform}/${arch}`);
  }
  // Using the go.mod version even on a newer developer machine preserves Folio's macOS 12 minimum.
  const version = readFileSync(path.join(moduleDir, "go.mod"), "utf8").match(/^go (\d+\.\d+\.\d+)\s*$/m)?.[1];
  if (!version) throw new Error("Set the exact Go patch version in native/certsign/go.mod.");
  const env = { ...process.env, GOTOOLCHAIN: `go${version}`, GOWORK: "off", GOOS: goOS, GOARCH: goArch, CGO_ENABLED: "1" };
  if (platform === "darwin") env.MACOSX_DEPLOYMENT_TARGET = "12.0";
  if (platform === "win32" && process.platform !== "win32" && !env.CC) env.CC = "x86_64-w64-mingw32-gcc";
  try {
    execFileSync(process.execPath, [path.join(moduleDir, "go.mjs"), ...args], { cwd: moduleDir, env, stdio: "inherit" });
  } catch (cause) {
    throw new Error(`Could not ${args[0]} the certificate signer for ${platform}/${arch}. This step requires Go ${version} and a C compiler for that target.`, { cause });
  }
}

function buildSigner(platform, arch, directory) {
  mkdirSync(directory, { recursive: true });
  const executable = path.join(directory, platform === "win32" ? "folio-certsign.exe" : "folio-certsign");
  runGo(platform, arch, ["build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", executable, "."]);
  return executable;
}

// electron-builder calls beforePack separately for x64 and arm64. Its universal packer then joins the
// two Mach-O executables with lipo, before signing the final .app. Keep the inputs in different directories.
export function beforePack({ electronPlatformName, arch, packager }) {
  const name = Arch[arch];
  buildSigner(electronPlatformName, name, path.join(binDir, "pack", packager.platform.buildConfigurationKey, name));
}

function checkSigner(executable) {
  // An unknown operation exits before the helper opens the user's certificate store.
  const response = execFileSync(executable, [], {
    input: '{"action":"unsupported"}\n', encoding: "utf8", timeout: 10_000, windowsHide: true,
  });
  assert.deepEqual(JSON.parse(response), { error: "invalid_request" }, `Unexpected response from ${executable}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  if (!args.length) {
    checkSigner(buildSigner(process.platform, process.arch, binDir));
  } else if (args.length === 1 && args[0] === "--test") {
    runGo(process.platform, process.arch, ["test", "./..."]);
  } else if (args.length === 2 && args[0] === "--check") {
    checkSigner(path.resolve(args[1]));
  } else {
    throw new Error("Usage: node scripts/build-certificate-signer.mjs [--test | --check path-to-executable]");
  }
}
