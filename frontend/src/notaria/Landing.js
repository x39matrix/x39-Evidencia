import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { FileText, PenLine, Anchor, ShieldCheck, Users, Coins, Atom, SearchCheck, KeyRound, Clock, MessageCircle } from 'lucide-react';
import { Nav } from './Nav';
import { useAuth } from './NotariaApp';
import { useLang } from './i18n';
import { api, goLogin } from './api';

const DEMO_CERT_ID = '31e1cf09a5b2a74cd978';
const STEP_ICONS = [FileText, PenLine, Anchor];

// La criptografía que usa la Notaría de verdad: [algoritmo, estándar, para qué sirve].
const CRYPTO = {
  es: { title: 'Criptografía', sub: 'Estándares abiertos que cualquiera puede comprobar.', items: [
    ['ML-DSA-87', 'NIST FIPS 204', 'Cofirma post-cuántica desde una máquina sin red'],
    ['OpenTimestamps', 'Bitcoin', 'La fecha queda anclada en un bloque de Bitcoin'],
    ['SHA-256', 'Web Crypto', 'La huella se calcula en tu navegador'],
    ['X-Wing', 'ML-KEM-768 + X25519', 'Chat cifrado de extremo a extremo'],
  ] },
  en: { title: 'Cryptography', sub: 'Open standards anyone can check.', items: [
    ['ML-DSA-87', 'NIST FIPS 204', 'Post-quantum co-signature from an air-gapped machine'],
    ['OpenTimestamps', 'Bitcoin', 'The date is anchored in a Bitcoin block'],
    ['SHA-256', 'Web Crypto', 'The fingerprint is computed in your browser'],
    ['X-Wing', 'ML-KEM-768 + X25519', 'End-to-end encrypted chat'],
  ] },
  zh: { title: '密码学', sub: '任何人都能核查的开放标准。', items: [
    ['ML-DSA-87', 'NIST FIPS 204', '来自离线设备的抗量子联署签名'],
    ['OpenTimestamps', 'Bitcoin', '日期锚定在比特币区块中'],
    ['SHA-256', 'Web Crypto', '指纹在你的浏览器中计算'],
    ['X-Wing', 'ML-KEM-768 + X25519', '端到端加密聊天'],
  ] },
  ja: { title: '暗号技術', sub: '誰でも検証できるオープン標準。', items: [
    ['ML-DSA-87', 'NIST FIPS 204', 'ネットワークから隔離された端末による耐量子副署名'],
    ['OpenTimestamps', 'Bitcoin', '日付をビットコインのブロックに固定'],
    ['SHA-256', 'Web Crypto', 'ハッシュはブラウザ内で計算'],
    ['X-Wing', 'ML-KEM-768 + X25519', 'エンドツーエンド暗号化チャット'],
  ] },
  ar: { title: 'التشفير', sub: 'معايير مفتوحة يمكن لأي شخص التحقق منها.', items: [
    ['ML-DSA-87', 'NIST FIPS 204', 'توقيع مشترك مقاوم للحوسبة الكمية من جهاز غير متصل بالشبكة'],
    ['OpenTimestamps', 'Bitcoin', 'التاريخ مثبت في كتلة بيتكوين'],
    ['SHA-256', 'Web Crypto', 'تُحسب البصمة في متصفحك'],
    ['X-Wing', 'ML-KEM-768 + X25519', 'دردشة مشفرة من طرف إلى طرف'],
  ] },
  uk: { title: 'Криптографія', sub: 'Відкриті стандарти, які може перевірити будь-хто.', items: [
    ['ML-DSA-87', 'NIST FIPS 204', 'Постквантовий контрпідпис з машини без доступу до мережі'],
    ['OpenTimestamps', 'Bitcoin', 'Дату закріплено в блоці Bitcoin'],
    ['SHA-256', 'Web Crypto', 'Хеш обчислюється у вашому браузері'],
    ['X-Wing', 'ML-KEM-768 + X25519', 'Чат із наскрізним шифруванням'],
  ] },
  ru: { title: 'Криптография', sub: 'Открытые стандарты, которые может проверить любой.', items: [
    ['ML-DSA-87', 'NIST FIPS 204', 'Постквантовая контрподпись с машины без доступа к сети'],
    ['OpenTimestamps', 'Bitcoin', 'Дата закреплена в блоке Bitcoin'],
    ['SHA-256', 'Web Crypto', 'Хеш вычисляется в вашем браузере'],
    ['X-Wing', 'ML-KEM-768 + X25519', 'Чат со сквозным шифрованием'],
  ] },
};

export default function Landing() {
  const { user } = useAuth();
  const { t, lang } = useLang();
  const crypto = CRYPTO[lang] || CRYPTO.en;
  const navigate = useNavigate();
  const [demoProof, setDemoProof] = useState(null);

  useEffect(() => {
    api.publicProof(DEMO_CERT_ID).then(setDemoProof).catch(() => setDemoProof(null));
  }, []);

  const createFirst = () => {
    if (user) navigate('/crear');
    else goLogin('/crear');
  };

  const steps = [1, 2, 3].map((n, i) => ({
    icon: STEP_ICONS[i],
    t: t(`landing.s${n}t`),
    d: t(`landing.s${n}d`),
  }));

  return (
    <div data-testid="landing-page">
      <Nav />
      <main className="nt-wrap">
        <div className="nt-card" role="status" data-testid="beta-banner" style={{ marginBottom: 18, padding: '10px 14px', borderLeft: '3px solid var(--seal)', fontSize: 13, lineHeight: 1.5 }}>
          {t('landing.betaBanner')}
        </div>
        <section className="nt-hero">
          <div>
            <div className="nt-label" style={{ marginBottom: 14 }}>{t('landing.tag')}</div>
            <h1>{t('landing.h1')}</h1>
            <p className="nt-serif" style={{ fontSize: 20, fontStyle: 'italic', color: 'var(--fg)', margin: '0 0 14px', maxWidth: '44ch', lineHeight: 1.35 }}>
              {t('landing.h1b')}
            </p>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', margin: '0 0 14px' }} data-testid="hero-pq-chips">
              <span className="nt-mono" style={{ fontSize: 11, border: '1px solid var(--seal)', color: 'var(--seal)', borderRadius: 999, padding: '4px 10px' }}>
                {t('landing.chipPq')}
              </span>
              <span className="nt-mono" style={{ fontSize: 11, border: '1px solid var(--border)', color: 'var(--muted)', borderRadius: 999, padding: '4px 10px' }}>
                {t('landing.chipBtc')}
              </span>
              <span className="nt-mono" style={{ fontSize: 11, border: '1px solid var(--border)', color: 'var(--muted)', borderRadius: 999, padding: '4px 10px' }}>
                {t('landing.chipTrust')}
              </span>
              <span className="nt-mono" data-testid="hero-chip-cold" style={{ fontSize: 11, border: '1px solid var(--border)', color: 'var(--muted)', borderRadius: 999, padding: '4px 10px' }}>
                {t('landing.chipCold')}
              </span>
              <span className="nt-mono" data-testid="hero-chip-node" style={{ fontSize: 11, border: '1px solid var(--border)', color: 'var(--muted)', borderRadius: 999, padding: '4px 10px' }}>
                {t('landing.chipNode')}
              </span>
            </div>
            <p>{t('landing.sub')}</p>
            <div className="nt-hero-actions">
              <button className="nt-btn nt-btn-seal" onClick={createFirst} data-testid="landing-cta-start">
                {t('landing.ctaPrimary')}
              </button>
              <Link to={`/certificado/${DEMO_CERT_ID}#verificador`} className="nt-btn nt-btn-ghost" data-testid="landing-cta-verify-self">
                {t('landing.ctaVerifySelf')}
              </Link>
            </div>
          </div>
          <div role="link" tabIndex={0} onClick={() => navigate(`/certificado/${DEMO_CERT_ID}`)}
            onKeyDown={(e) => { if (e.key === 'Enter') navigate(`/certificado/${DEMO_CERT_ID}`); }}
            className="nt-hero-visual" style={{ display: 'block', color: 'inherit', cursor: 'pointer' }} data-testid="hero-demo-cert">
            <div style={{ textAlign: 'center', borderBottom: '1px solid var(--border)', paddingBottom: 16, marginBottom: 18 }}>
              <div className="nt-label" style={{ marginBottom: 4 }}>X-39 Evidencia</div>
              <div className="nt-serif" style={{ fontSize: 26, fontWeight: 600 }}>{t('landing.certTitle')}</div>
            </div>
            <div className="nt-label">{t('landing.certHashLabel')}</div>
            <div className="nt-mono" style={{ fontSize: 11, marginBottom: 14 }} data-testid="hero-cert-hash">
              {demoProof ? demoProof.content_hash : 'eda1fa21b0a3c67ddaede7f84bd2641810594670a1438cd955f88fa6098d6967'}
            </div>
            <div className="nt-label">{t('landing.certAnchorLabel')}</div>
            {demoProof ? (
              demoProof.ots_status === 'anchored_btc' ? (
                <>
                  <span className="nt-badge nt-badge-sealed" style={{ marginBottom: 8 }} data-testid="hero-cert-anchor">{t('ag.badgeConfirmedIn')}{demoProof.btc_block}</span>
                  <div>
                    <a className="nt-mono" style={{ fontSize: 11, color: 'var(--seal)', textDecoration: 'underline' }}
                      href={`https://mempool.space/block/${demoProof.btc_block}`} target="_blank" rel="noreferrer"
                      onClick={(e) => e.stopPropagation()} data-testid="hero-block-link">
                      {t('protect.viewBlock')} →
                    </a>
                  </div>
                </>
              ) : (
                <span className="nt-badge nt-badge-draft" style={{ marginBottom: 8 }} data-testid="hero-cert-anchor">{t('landing.certRealBadgePending')}</span>
              )
            ) : (
              <span className="nt-badge nt-badge-sealed" style={{ marginBottom: 8 }}>{t('landing.certMockBadge')}</span>
            )}
            {demoProof?.pq && (
              <>
                <div className="nt-label" style={{ marginTop: 12 }}>{t('ag.pqSig')}</div>
                <div className="nt-mono" style={{ fontSize: 11 }} data-testid="hero-cert-pq">ML-DSA-87 (FIPS-204)</div>
              </>
            )}
            <div className="nt-seal-stamp" style={{ width: 92, height: 92, marginTop: 16 }}>
              <span className="big">{t('landing.sealedStamp')}</span>
              <span className="sm">X-39 Evidencia</span>
            </div>
            {demoProof && (
              <div className="nt-note" style={{ textAlign: 'center', marginTop: 14, textDecoration: 'underline' }} data-testid="hero-cert-open">
                {t('landing.certOpen')} →
              </div>
            )}
          </div>
        </section>

        <section className="nt-steps">
          {steps.map((s, i) => (
            <div className="nt-step" key={s.t}>
              <div className="n">{String(i + 1).padStart(2, '0')}</div>
              <h3><s.icon size={15} strokeWidth={1.5} style={{ verticalAlign: '-2px', marginRight: 6 }} />{s.t}</h3>
              <p>{s.d}</p>
            </div>
          ))}
        </section>

        <section className="nt-crypto" data-testid="landing-crypto">
          <div className="nt-crypto-head">
            <KeyRound size={20} strokeWidth={1.5} aria-hidden="true" />
            <h2>{crypto.title}</h2>
          </div>
          <p className="nt-note" style={{ fontSize: 14, margin: '6px 0 0' }}>{crypto.sub}</p>
          <div className="nt-crypto-grid">
            {crypto.items.map(([alg, std, desc]) => (
              <div className="nt-crypto-tile" key={alg}>
                <div className="nt-crypto-alg">{alg}</div>
                <div className="nt-crypto-std">{std}</div>
                <p>{desc}</p>
              </div>
            ))}
          </div>
        </section>

        <section style={{ marginBottom: 20 }} data-testid="landing-protect">
          <h2 className="nt-serif" style={{ fontSize: 26, fontWeight: 600, margin: '0 0 16px' }}>{t('protect.title')}</h2>
          <div className="nt-steps nt-steps-2x2" style={{ margin: 0 }}>
            {[{ icon: Anchor, k: 'b1' }, { icon: Atom, k: 'b2' }, { icon: SearchCheck, k: 'b3' }, { icon: Clock, k: 'b4' }].map(({ icon: Icon, k }) => (
              <div className="nt-step" key={k}>
                <Icon size={20} strokeWidth={1.5} color="var(--seal)" />
                <h3>{t(`protect.${k}t`)}</h3>
                <p>{t(`protect.${k}d`)}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="nt-card nt-card-pad" style={{ marginBottom: 20 }} data-testid="landing-forwho">
          <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
            <Users size={22} strokeWidth={1.5} color="var(--seal)" style={{ flexShrink: 0, marginTop: 2 }} />
            <div>
              <h2 className="nt-serif" style={{ fontSize: 22, margin: '0 0 8px', fontWeight: 600 }}>{t('landing.forWhoTitle')}</h2>
              <p className="nt-note" style={{ fontSize: 14, maxWidth: '70ch', margin: 0 }}>{t('landing.forWho')}</p>
            </div>
          </div>
        </section>

        <section className="nt-card nt-card-pad" style={{ marginBottom: 20 }} data-testid="landing-pricing">
          <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
            <Coins size={22} strokeWidth={1.5} color="var(--seal)" style={{ flexShrink: 0, marginTop: 2 }} />
            <div>
              <h2 className="nt-serif" style={{ fontSize: 22, margin: '0 0 8px', fontWeight: 600 }}>
                {t('landing.priceTitle')}
              </h2>
              <p className="nt-note" style={{ fontSize: 14, maxWidth: '70ch', margin: 0 }}>{t('landing.priceBody')}</p>
            </div>
          </div>
        </section>

        <section className="nt-card nt-card-pad" style={{ marginBottom: 64 }}>
          <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
            <ShieldCheck size={22} strokeWidth={1.5} color="var(--seal)" style={{ flexShrink: 0, marginTop: 2 }} />
            <div>
              <h2 className="nt-serif" style={{ fontSize: 22, margin: '0 0 8px', fontWeight: 600 }}>{t('landing.honestyTitle')}</h2>
              <p className="nt-note" style={{ fontSize: 14, maxWidth: '70ch', margin: 0 }}>{t('landing.honestyBody')}</p>
              <a href="https://github.com/x39matrix/x39-Evidencia" target="_blank" rel="noreferrer" style={{ display: 'inline-block', marginTop: 10, fontSize: 14, color: 'var(--seal)', textDecoration: 'underline' }} data-testid="landing-github-link">{t('landing.codeLink')}</a>
            </div>
          </div>
        </section>

        <section className="nt-card nt-card-pad" style={{ marginBottom: 64 }} data-testid="landing-comms">
          <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
            <MessageCircle size={22} strokeWidth={1.5} color="var(--seal)" style={{ flexShrink: 0, marginTop: 2 }} />
            <div>
              <h2 className="nt-serif" style={{ fontSize: 22, margin: '0 0 8px', fontWeight: 600 }}>{t('landing.commsT')}</h2>
              <p className="nt-note" style={{ fontSize: 14, maxWidth: '70ch', margin: 0 }}>{t('landing.commsBody')}</p>
              <Link to="/comunicaciones" style={{ display: 'inline-block', marginTop: 10, fontSize: 14, color: 'var(--seal)', textDecoration: 'underline' }} data-testid="landing-comms-link">{t('landing.commsLink')}</Link>
            </div>
          </div>
        </section>
      </main>
      <footer style={{ borderTop: '1px solid var(--border)', padding: '24px 0' }}>
        <div className="nt-wrap" style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
          <span className="nt-note">{t('landing.footer')}</span>
          <span className="nt-note nt-mono" style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
            <a href="https://github.com/x39matrix/x39-Evidencia" target="_blank" rel="noreferrer" style={{ color: 'var(--fg)', textDecoration: 'underline' }} data-testid="footer-github">{t('footer.github')}</a>
            <a href="mailto:grants@x39matrix.org" style={{ color: 'var(--fg)', textDecoration: 'underline' }} data-testid="footer-contact">{t('footer.contact')}</a>
            <Link to="/privacidad" style={{ color: 'var(--fg)', textDecoration: 'underline' }} data-testid="footer-privacy">{t('footer.privacy')}</Link>
            <Link to="/app" style={{ color: 'var(--fg)', textDecoration: 'underline' }} data-testid="footer-app">{t('footer.app')}</Link>
            <Link to="/comunicaciones" style={{ color: 'var(--fg)', textDecoration: 'underline' }} data-testid="footer-comms">{t('footer.comms')}</Link>
            <span>OpenTimestamps · SHA-256 · ML-DSA-87</span>
          </span>
        </div>
      </footer>
    </div>
  );
}
