// The native library builds an issuer chain while listing on Windows and
// while signing on macOS. Keep both lookups offline without modifying the
// module cache or maintaining a vendored copy of the cryptographic backend.
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const cwd = fileURLToPath(new URL('.', import.meta.url));
const options = { cwd, encoding: 'utf8', windowsHide: true };
const [command, ...args] = process.argv.slice(2);
if (!['build', 'test', 'vet'].includes(command)) throw new Error('Expected go build, test or vet');
const target = execFileSync('go', ['env', 'GOOS'], options).trim();

function patchOnce(source, before, after) {
  if (!source.includes(before) || source.indexOf(before) !== source.lastIndexOf(before)) throw new Error('Unexpected native API call site');
  return source.replace(before, after);
}

if (target === 'darwin' || target === 'windows') {
  const module = 'github.com/sukujgrg/go-certstore';
  const version = 'v0.2.2';
  const dependency = JSON.parse(execFileSync('go', ['mod', 'download', '-json', module + '@' + version], options));
  if (dependency.Sum !== 'h1:a+8TeEoa+7sGk2BemODVSSWYvzZPSZnUq7SQo/Pyes0=') throw new Error('Unexpected certstore module');
  const originalFile = 'certstore_' + target + '.go';
  let source = readFileSync(join(dependency.Dir, originalFile), 'utf8');
  const expectedHash = target === 'windows'
    ? 'dbe08f80afb2bf001dd5315969b9fc711d188a5050a32b9ed6cc4b404ffc6a27'
    : '2288ed78d14257a307525f42c1bdbd1141d27d3a46c7c73b3a951b809209345c';
  if (createHash('sha256').update(source).digest('hex') !== expectedHash) throw new Error('Unexpected certstore source');
  if (target === 'windows') {
    source = patchOnce(source, '\n\t\t\t0,\n\t\t\tC.CERT_CHAIN_FIND_BY_ISSUER,',
      '\n\t\t\tC.CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG,\n\t\t\tC.CERT_CHAIN_FIND_BY_ISSUER,');
    // Only the explicit sign action calls Signer. An imported, strongly
    // protected A1 key may require the Windows provider's own approval UI.
    source = patchOnce(source, 'windowsPrivateKeyAcquireFlags(cachePrivateKey),',
      'windowsPrivateKeyAcquireFlags(cachePrivateKey) &^ C.CRYPT_ACQUIRE_SILENT_FLAG,');
    source = patchOnce(source, 'var flags C.DWORD = C.NCRYPT_SILENT_FLAG', 'var flags C.DWORD');
  } else {
    source = patchOnce(source, 'C.SecTrustEvaluateWithError(trust, &cfErr)',
      'if C.SecTrustSetNetworkFetchAllowed(trust, 0) != C.errSecSuccess { return []*x509.Certificate{cert}, nil }\n\tC.SecTrustEvaluateWithError(trust, &cfErr)');
  }
  source += '\nconst FolioOfflineChains = true\n';
  const scratch = mkdtempSync(join(tmpdir(), 'folio-offline-certstore-'));
  const local = join(scratch, 'certstore');
  cpSync(dependency.Dir, local, { recursive: true });
  const patched = join(local, originalFile);
  chmodSync(patched, 0o600);
  writeFileSync(patched, source);
  const modfile = join(scratch, 'build.mod');
  // Go resolves relative replace paths from the module root. Use a quoted,
  // absolute path to support spaces, Windows drives and CI worktrees.
  writeFileSync(modfile, readFileSync(join(cwd, 'go.mod'), 'utf8') +
    '\nreplace ' + module + ' ' + version + ' => ' + JSON.stringify(local.replaceAll('\\', '/')) + '\n');
  copyFileSync(join(cwd, 'go.sum'), join(scratch, 'build.sum'));
  args.unshift('-modfile', modfile);
}
const result = spawnSync('go', [command, ...args], { ...options, stdio: 'inherit' });
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
