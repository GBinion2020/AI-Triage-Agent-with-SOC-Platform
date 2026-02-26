import { FolderOpen, LayoutDashboard, Shield } from 'lucide-react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';

export default function SidebarLayout() {
  const location = useLocation();

  return (
    <div className="shell" style={{ backgroundColor: '#050a16' }}>
      <aside className="sidebar">
        <Link to="/" className="logo" aria-label="SOC Console">
          <Shield size={18} />
        </Link>
        <nav className="side-nav">
          <NavLink to="/" end className={({ isActive }) => `side-link ${isActive ? 'active' : ''}`} title="Dashboard">
            <LayoutDashboard size={16} />
          </NavLink>
          <NavLink to="/cases" className={({ isActive }) => `side-link ${isActive ? 'active' : ''}`} title="Cases">
            <FolderOpen size={16} />
          </NavLink>
        </nav>
      </aside>

      <div className="main-area" style={{ backgroundColor: '#050a16' }}>
        <header className="topbar">
          <div className="crumb">SOC CONSOLE / {location.pathname.startsWith('/cases') ? 'Cases' : 'Dashboard'}</div>
          <div className="top-pills">
            <span className="pill live">LIVE</span>
          </div>
        </header>
        <main className="content-area" style={{ backgroundColor: '#050a16' }}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
