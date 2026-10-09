import React from 'react';
import { Link } from 'react-router-dom';
import { Nav } from './Nav';
import { useLang } from './i18n';

// Página de X-39 Evidencia para Android (release 0.3.3). El APK y sus ficheros de verificación se sirven
// desde /app/ en este mismo dominio; /app/x39.apk es una copia del mismo APK para el enlace antiguo.
const APK = 'x39-0.3.3-release.apk';
const RELEASE = 'https://github.com/x39matrix/x39-Evidencia/releases/tag/evidencia-0.3.3';
const VERIF = [`${APK}.sha256`, `${APK}.tsr`, `${APK}.cadena.pem`, `${APK}.ots`, 'anf_root.pem'];
const CMDS = [
  `sha256sum ${APK}`,
  `apksigner verify --print-certs ${APK}`,
  `openssl ts -verify -data ${APK} -in ${APK}.tsr -CAfile anf_root.pem -untrusted ${APK}.cadena.pem`,
  `ots verify ${APK}.ots`,
].join('\n');

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
          <p className="nt-mono" style={MONO}>APK SHA-256: 4c5c3a321a97f8bb45a83b5f8c878d27608b23499921df52fa079212ef330f03</p>
          <p className="nt-mono" style={MONO}>Certificado de firma SHA-256: 72f0745f993605b1b3cd30966162b6d98d84fcacbd23e2e07e24c3d15f7d8935</p>
          <p className="nt-mono" style={{ ...MONO, display: 'flex', flexWrap: 'wrap', gap: '4px 14px', marginTop: 10 }} data-testid="app-verif-files">
            {VERIF.map((f) => (
              <a key={f} href={`/app/${f}`} download={f} style={A}>{f}</a>
            ))}
          </p>
          {section('appe.clocksT', ['appe.clock1', 'appe.clock2'])}
          {section('appe.verifyT', ['appe.verify1'])}
          <pre className="nt-code" dir="ltr" data-testid="app-verify-cmds">{CMDS}</pre>
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
