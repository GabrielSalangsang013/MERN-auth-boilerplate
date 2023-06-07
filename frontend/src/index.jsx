import React from 'react';
import ReactDOM from 'react-dom/client';
import {BrowserRouter as Router, Route, Routes, Navigate} from 'react-router-dom';

import App from './pages/App';
import Home from './pages/Home';
import Login from './pages/Login';
import LoginVerificationCode from './pages/LoginVerificationCode';
import Register from './pages/Register';
import AccountActivation from './pages/AccountActivation';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';

import MFARoutes from "./routes/MFARoutes";
import PublicRoutes from "./routes/PublicRoutes";
import PrivateRoutes from "./routes/PrivateRoutes";

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  // <React.StrictMode>
      <Router>
        <Routes>
            {/* -------------- LANDING PAGE ROUTE ------------ */}
            <Route path='/' exact element={<App />}/>

            <Route element={<MFARoutes />}>
                <Route path='/login/verify-code' exact element={<LoginVerificationCode />}/>
            </Route>

            {/* -------------- PUBLIC ROUTES ------------ */}
            <Route element={<PublicRoutes />}>
              <Route path='/login' exact element={<Login />}/>
              <Route path='/register' exact element={<Register />}/>
              <Route path='/activate/:token' exact element={<AccountActivation  />}/>
              <Route path='/forgot-password' exact element={<ForgotPassword />}/>
              <Route path='/reset-password/:token/:csrfToken' exact element={<ResetPassword />}/>
            </Route>

            {/* -------------- PRIVATE ROUTES REQUIRES JWT AUTHENTICATION TOKEN ------------ */}
            <Route element={<PrivateRoutes />}>
              <Route path="/home" element={<Home />} />
            </Route>

            <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Router>
  // </React.StrictMode>
);