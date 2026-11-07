import React from 'react';
import { Link } from 'react-router-dom';
import { Nav } from './Nav';
import { useLang } from './i18n';

// Página de X-39 Evidencia para Android (release 0.3.5). El APK y sus ficheros de verificación se sirven
// desde /app/ en este mismo dominio; /app/x39.apk es una copia del APK actual para el enlace antiguo.
// La 0.3.4 se mantiene como versión anterior durante una release más.
const APK = 'x39-0.3.5-release.apk';
const APK_SHA256 = '6e8073201b8abf623350223fa95c58e018e13f08b8a6e95f4925c8c642e2a3c6';
const APK_BYTES = '6 327 111 bytes';
const CERT_SHA256 = '8d46f850509ebfd4778156195c14bb69719dd09f799a4fb661b940e7e2b22fbe';
const RELEASE = 'https://github.com/x39matrix/x39-Evidencia/releases/tag/evidencia-0.3.5';
// Ancla OpenTimestamps confirmada y comprobada contra nodo propio (07/11/2026).
const BTC_BLOCK = '974912';
const BTC_BLOCK_HASH = '00000000000000000000c7df95b473b17aa2f75fda58ab56a875c613e2577a96';
const VERIF = [`${APK}.sha256`, `${APK}.ots`, `${APK}.tsr`, `${APK}.cadena.pem`, `${APK}.sello.txt`, 'anf_root.pem'];
const CMDS = [
  `sha256sum ${APK}`,
  `apksigner verify --print-certs ${APK}`,
  `openssl ts -verify -data ${APK} -in ${APK}.tsr -CAfile anf_root.pem -untrusted ${APK}.cadena.pem`,
  `ots verify ${APK}.ots`,
  `# → Success! Bitcoin block ${BTC_BLOCK} attests existence as of 2026-11-07 08:40:18 UTC (in your local time)`,
].join('\n');
const PREV_APK = 'x39-0.3.4-release.apk';
const PREV_SHA256 = '9c9d654cc9712c60e2803f1bf424fcf2bf409141c4a7d0f43eaa37b67b2d45ef';
const PREV_RELEASE = 'https://github.com/x39matrix/x39-Evidencia/releases/tag/evidencia-0.3.4';

const P = { fontSize: 14, lineHeight: 1.6, margin: '0 0 12px' };
const H2 = { fontSize: 20, fontWeight: 600, margin: '24px 0 10px' };
const A = { color: 'var(--seal)', textDecoration: 'underline' };
const MONO = { fontSize: 12, lineHeight: 1.6, margin: '0 0 6px' };

export default function AppMovil() {
  const { t } = useLang();
  const section = (title, keys) => (
    <>
      <h2 className="nt-serif" style={H2}>{t(title)}</h2>
      {keys.map((k) => (
        <p key={k} className="nt-note" style={P}>{t(k)}</p>
      ))}
    </>
  );
  return (
    <div data-testid="app-page">
      <Nav />
      <main className="nt-wrap" style={{ padding: '40px 20px 80px' }}>
        <div className="nt-card nt-card-pad" style={{ maxWidth: 760, margin: '0 auto' }}>
          <h1 className="nt-serif" style={{ fontSize: 28, fontWeight: 600, margin: '0 0 16px' }}>{t('appe.title')}</h1>
          <p className="nt-note" style={P}>{t('appe.sub')}</p>
          {section('appe.whatT', ['appe.what1', 'appe.what2', 'appe.what3'])}
          {section('appe.dlT', ['appe.dl1'])}
          <p style={P}>
            <a href={`/app/${APK}`} download={APK} style={{ ...A, fontWeight: 600 }} data-testid="app-download">{t('appe.dlLink')}</a>
          </p>
          <p style={P}>
            <a href={RELEASE} target="_blank" rel="noreferrer" style={A} data-testid="app-github-release">{t('appe.dlLink2')}</a>
          </p>
          <p className="nt-mono" style={MONO} data-testid="app-sha256">APK SHA-256: {APK_SHA256}</p>
          <p className="nt-mono" style={MONO} data-testid="app-size">{APK} · {APK_BYTES}</p>
          <p className="nt-mono" style={MONO}>Certificado de firma SHA-256: {CERT_SHA256}</p>
          <p className="nt-mono" style={MONO} data-testid="app-btc-block">Bitcoin {BTC_BLOCK} · {BTC_BLOCK_HASH}</p>
          <p className="nt-mono" style={{ ...MONO, display: 'flex', flexWrap: 'wrap', gap: '4px 14px', marginTop: 10 }} data-testid="app-verif-files">
            {VERIF.map((f) => (
              <a key={f} href={`/app/${f}`} download={f} style={A}>{f}</a>
            ))}
          </p>
          {section('appe.clocksT', ['appe.clock1', 'appe.clock2'])}
          {section('appe.verifyT', ['appe.verify1'])}
          <pre className="nt-code" dir="ltr" data-testid="app-verify-cmds">{CMDS}</pre>
          <h2 className="nt-serif" style={H2}>{t('appe.prevT')}</h2>
          <p className="nt-note" style={P}>{t('appe.prev1')}</p>
          <p style={{ ...P, display: 'flex', flexWrap: 'wrap', gap: '4px 18px' }} data-testid="app-prev">
            <a href={`/app/${PREV_APK}`} download={PREV_APK} style={A} data-testid="app-prev-download">{t('appe.prevLink')}</a>
            <a href={PREV_RELEASE} target="_blank" rel="noreferrer" style={A} data-testid="app-prev-github-release">{t('appe.prevGh')}</a>
          </p>
          <p className="nt-mono" style={MONO}>{PREV_APK} SHA-256: {PREV_SHA256}</p>
          {section('appe.permsT', ['appe.perms1', 'appe.perms2'])}
          {section('appe.srcT', ['appe.src1'])}
          <p style={{ margin: '28px 0 0', display: 'flex', flexWrap: 'wrap', gap: 18 }}>
            <Link to="/comunicaciones" style={A} data-testid="app-to-comms">{t('appe.toComms')}</Link>
            <Link to="/" style={A} data-testid="app-back">{t('appe.back')}</Link>
          </p>
        </div>
      </main>
    </div>
  );
}
