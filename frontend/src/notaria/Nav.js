import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { LogOut, LockKeyhole } from 'lucide-react';
import { useAuth } from './NotariaApp';
import { useLang, LANGS } from './i18n';
import { api, goLogin } from './api';

export const Nav = () => {
  const { user, setUser } = useAuth();
  const { lang, setLang, t } = useLang();
  const navigate = useNavigate();

  const logout = async () => {
    try { await api.logout(); } catch { /* noop */ }
    setUser(null);
    navigate('/');
  };

  return (
    <nav className="nt-nav">
      <div className="nt-wrap nt-nav-inner">
        <Link to={user ? '/panel' : '/'} className="nt-brand" data-testid="nav-brand">
          <LockKeyhole size={26} strokeWidth={2} color="var(--brand)" aria-hidden="true" data-testid="nav-logo-img" />
          X-39 Evidencia
        </Link>
        <div className="nt-nav-links">
          <Link to="/verificar" className="nt-btn nt-btn-ghost" data-testid="nav-verify-link">{t('nav.verify')}</Link>
          {user ? (
            <>
              <Link to="/panel" className="nt-btn nt-btn-ghost" data-testid="nav-panel-link">{t('nav.panel')}</Link>
              <button className="nt-btn nt-btn-ghost" onClick={logout} data-testid="nav-logout-btn" aria-label="Log out">
                <LogOut size={15} strokeWidth={1.5} />
              </button>
            </>
          ) : (
            <button className="nt-btn nt-btn-primary" onClick={() => goLogin('/panel')} data-testid="nav-login-btn">
              {t('nav.login')}
            </button>
          )}
          <span className="nt-langbar" data-testid="lang-toggle-btn" role="group" aria-label="Language">
            {LANGS.map((l) => (
              <button key={l.code} className={`nt-langflag ${lang === l.code ? 'on' : ''}`}
                onClick={() => setLang(l.code)} data-testid={`lang-btn-${l.code}`} title={l.name || l.label}>
                {l.flag ? <><span aria-hidden="true">{l.flag}</span> </> : null}<span className={l.flag ? 'nt-langlabel' : 'nt-langlabel nt-langlabel-solo'}>{l.label}</span>
              </button>
            ))}
          </span>
          <span className="nt-brand-mark" data-testid="nav-brand-mark">x39</span>
        </div>
      </div>
    </nav>
  );
};
