import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Plus, ChevronRight, KeyRound } from 'lucide-react';
import { Nav } from './Nav';
import { useAuth } from './NotariaApp';
import { useLang } from './i18n';
import { api } from './api';

const Badge = ({ status, ots, t }) => {
  if (status !== 'sealed') return <span className="nt-badge nt-badge-pending">{t('panel.badgePending')}</span>;
  if (ots?.status === 'anchored_btc') return <span className="nt-badge nt-badge-sealed">{t('panel.badgeConfirmed')}{ots.btc_block}</span>;
  return <span className="nt-badge nt-badge-draft">{t('panel.badgeSealedPending')}</span>;
};

// Cifras del perfil. Sin correo: la identidad es la llave.
const STATS = {
  es: ['Acuerdos', 'Sellados', 'En Bitcoin'],
  en: ['Agreements', 'Sealed', 'On Bitcoin'],
  zh: ['协议', '已封存', '已上链比特币'],
  ja: ['合意', '封印済み', 'ビットコイン上'],
  ar: ['الاتفاقات', 'مختومة', 'في بيتكوين'],
  uk: ['Угоди', 'Запечатано', 'У Bitcoin'],
  ru: ['Соглашения', 'Запечатано', 'В Bitcoin'],
};

export default function Panel() {
  const { user } = useAuth();
  const { t, lang } = useLang();
  const [rows, setRows] = useState(null);
  const labels = STATS[lang] || STATS.en;
  const count = (fn) => (rows ? rows.filter(fn).length : '—');

  useEffect(() => {
    api.listAgreements().then(setRows).catch(() => setRows([]));
  }, []);

  return (
    <div data-testid="panel-page">
      <Nav />
      <main className="nt-wrap" style={{ padding: '40px 20px 80px' }}>
        <section className="nt-profile" data-testid="panel-profile">
          <div className="nt-avatar" aria-hidden="true"><KeyRound size={34} strokeWidth={1.5} /></div>
          <div className="nt-label">{t('panel.kicker')}</div>
          <h1>{t('panel.title')}</h1>
          <div className="nt-note nt-mono" data-testid="panel-user-email">{user?.email}</div>
          <div className="nt-stats" data-testid="panel-stats">
            <div className="nt-stat"><b>{rows ? rows.length : '—'}</b><span>{labels[0]}</span></div>
            <div className="nt-stat"><b>{count((a) => a.status === 'sealed')}</b><span>{labels[1]}</span></div>
            <div className="nt-stat"><b>{count((a) => a.ots?.status === 'anchored_btc')}</b><span>{labels[2]}</span></div>
          </div>
          <Link to="/crear" className="nt-btn nt-btn-primary" data-testid="panel-new-agreement-btn">
            <Plus size={16} strokeWidth={2} /> {t('panel.new')}
          </Link>
        </section>

        {rows === null && <div className="nt-note nt-mono">{t('common.loading')}</div>}

        {rows?.length === 0 && (
          <div className="nt-card nt-card-pad" style={{ textAlign: 'center' }} data-testid="panel-empty">
            <p className="nt-serif" style={{ fontSize: 22, margin: '0 0 6px' }}>{t('panel.emptyTitle')}</p>
            <p className="nt-note" style={{ margin: '0 0 20px' }}>{t('panel.emptyBody')}</p>
            <Link to="/crear" className="nt-btn nt-btn-primary" data-testid="panel-empty-create-btn">{t('panel.emptyCta')}</Link>
          </div>
        )}

        <div className="nt-list">
          {rows?.map((a) => (
            <Link to={`/acuerdo/${a.agreement_id}`} className="nt-agreement-row" key={a.agreement_id} data-testid={`agreement-row-${a.agreement_id}`}>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: 15, marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title}</div>
                <div className="nt-note nt-mono" style={{ fontSize: 11 }}>
                  {a.party_a}{a.party_b ? ` · ${a.party_b}` : ` · ${t('panel.waitingOther')}`}
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
                <Badge status={a.status} ots={a.ots} t={t} />
                <ChevronRight size={16} strokeWidth={1.5} color="var(--muted)" />
              </div>
            </Link>
          ))}
        </div>
      </main>
    </div>
  );
}
