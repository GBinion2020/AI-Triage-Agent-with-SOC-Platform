import { Navigate, Route, Routes, useParams } from 'react-router-dom';
import SidebarLayout from './components/SidebarLayout';
import DashboardPage from './pages/DashboardPage';
import CasesPage from './pages/CasesPage';
import CaseDetailPage from './pages/CaseDetailPage';

function NotFound() {
  return (
    <section className="card panel">
      <h2>Page Not Found</h2>
      <p>The requested page is not available.</p>
    </section>
  );
}

function LegacyTicketRedirect() {
  const { ticketId } = useParams();
  return <Navigate to={`/cases/${ticketId}`} replace />;
}

export default function App() {
  return (
    <Routes>
      <Route element={<SidebarLayout />}>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/dashboard" element={<Navigate to="/" replace />} />
        <Route path="/cases" element={<CasesPage />} />
        <Route path="/cases/:ticketId" element={<CaseDetailPage />} />
        <Route path="/tickets/:ticketId" element={<LegacyTicketRedirect />} />
        <Route path="/tickets/:ticketId/audit" element={<LegacyTicketRedirect />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
