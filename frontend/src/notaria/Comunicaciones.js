import React from 'react';
import { Link } from 'react-router-dom';
import { Nav } from './Nav';
import { useLang } from './i18n';

// Página de X-39 Comunicaciones (app aparte, beta cerrada): qué es, estado y límites.
const P = { fontSize: 14, lineHeight: 1.6, margin: '0 0 12px' };
const H2 = { fontSize: 20, fontWeight: 600, margin: '24px 0 10px' };
const A = { color: 'var(--seal)', textDecoration: 'underline' };

// En el texto traducido, [[...]] marca la expresión que enlaza a la página de la app de Evidencia (/app).
function conEnlaceApp(texto) {
  const m = /^(.*)\[\[(.+?)\]\](.*)$/s.exec(texto);
  if (!m) return texto;
  return <>{m[1]}<Link to="/app" style={A} data-testid="comms-to-app">{m[2]}</Link>{m[3]}</>;
}

export default function Comunicaciones() {
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
    <div data-testid="comunicaciones-page">
      <Nav />
      <main className="nt-wrap" style={{ padding: '40px 20px 80px' }}>
        <div className="nt-card nt-card-pad" style={{ maxWidth: 760, margin: '0 auto' }}>
          <h1 className="nt-serif" style={{ fontSize: 28, fontWeight: 600, margin: '0 0 16px' }}>{t('comms.title')}</h1>
          <p className="nt-note" style={P}>{t('comms.sub')}</p>
          {section('comms.howT', ['comms.how1', 'comms.how2'])}
          {section('comms.statusT', ['comms.status1'])}
          <p className="nt-note" style={P}>
            {t('comms.statusMail')}{' '}
            <a href="mailto:security@x39matrix.org" style={A} data-testid="comms-mail">security@x39matrix.org</a>
          </p>
          <h2 className="nt-serif" style={H2}>{t('comms.dlT')}</h2>
          <p className="nt-note" style={P}>{conEnlaceApp(t('comms.dl1'))}</p>
          {section('comms.whyT', ['comms.why1'])}
          {section('comms.limitsT', ['comms.limits1'])}
          <p style={{ margin: '28px 0 0' }}>
            <Link to="/" style={A} data-testid="comms-back">{t('comms.backEvidencia')}</Link>
          </p>
        </div>
      </main>
    </div>
  );
}
