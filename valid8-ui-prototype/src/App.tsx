// React is not needed in modern React with JSX Transform
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navigation from './components/Navigation';
import HeroSection from './components/HeroSection';
import FeaturesSection from './components/FeaturesSection';
import PricingSection from './components/PricingSection';
import LoginPage from './components/LoginPage';
import SignupPage from './components/SignupPage';
import Dashboard from './components/Dashboard';
import EnterpriseDashboard from './components/EnterpriseDashboard';
import EnterpriseSignup from './components/EnterpriseSignup';
import AccountPage from './components/AccountPage';
import Footer from './components/Footer';

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
        <Navigation />
        <Routes>
          <Route path="/" element={
            <>
              <HeroSection />
              <FeaturesSection />
              <PricingSection />
            </>
          } />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/signup" element={<SignupPage />} />
          <Route path="/enterprise-signup" element={<EnterpriseSignup />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/enterprise" element={<EnterpriseDashboard />} />
          <Route path="/account" element={<AccountPage />} />
        </Routes>
        <Footer />
      </div>
    </Router>
  );
}

export default App;
