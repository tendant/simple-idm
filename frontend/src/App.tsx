import { Route, Router } from '@solidjs/router';
import type { Component } from 'solid-js';
import { Suspense } from 'solid-js';

import Navigation from './components/Navigation';
import CreateLogin from './pages/CreateLogin';
import CreateRole from './pages/CreateRole';
import CreateUser from './pages/CreateUser';
import EditLogin from './pages/EditLogin';
import EditRole from './pages/EditRole';
import EditUser from './pages/EditUser';
import FindUsername from './pages/FindUsername';
import Login from './pages/Login';
import LoginDetail from './pages/LoginDetail';
import Logins from './pages/Logins';
import PasswordReset from './pages/PasswordReset';
import PasswordResetInit from './pages/PasswordResetInit';
import Roles from './pages/Roles';
import Settings from './pages/Settings';
import TwoFactorVerification from './pages/TwoFactorVerification';
import Users from './pages/Users';

const UsersPage: Component = () => {
  return (
    <div
      class="min-h-screen bg-gray-1"
    >
      <main
        class="py-10 px-4 sm:px-6 lg:px-8"
      >
        <Navigation />
        <Users />
      </main>
    </div>
  );
};

const CreateUserPage: Component = () => {
  return (
    <div
      class="min-h-screen bg-gray-1"
    >
      <main
        class="py-10 px-4 sm:px-6 lg:px-8"
      >
        <Navigation />
        <CreateUser />
      </main>
    </div>
  );
};

const EditUserPage: Component = () => {
  return (
    <div
      class="min-h-screen bg-gray-1"
    >
      <main
        class="py-10 px-4 sm:px-6 lg:px-8"
      >
        <Navigation />
        <EditUser />
      </main>
    </div>
  );
};

const RolesPage: Component = () => {
  return (
    <div
      class="min-h-screen bg-gray-1"
    >
      <main
        class="py-10 px-4 sm:px-6 lg:px-8"
      >
        <Navigation />
        <Roles />
      </main>
    </div>
  );
};

const CreateRolePage: Component = () => {
  return (
    <div
      class="min-h-screen bg-gray-1"
    >
      <main
        class="py-10 px-4 sm:px-6 lg:px-8"
      >
        <Navigation />
        <CreateRole />
      </main>
    </div>
  );
};

const EditRolePage: Component = () => {
  return (
    <div
      class="min-h-screen bg-gray-1"
    >
      <main
        class="py-10 px-4 sm:px-6 lg:px-8"
      >
        <Navigation />
        <Suspense>
          <EditRole />
        </Suspense>
      </main>
    </div>
  );
};

const LoginsPage: Component = () => {
  return (
    <div
      class="min-h-screen bg-gray-1"
    >
      <main
        class="py-10 px-4 sm:px-6 lg:px-8"
      >
        <Navigation />
        <Logins />
      </main>
    </div>
  );
};

const CreateLoginPage: Component = () => {
  return (
    <div
      class="min-h-screen bg-gray-1"
    >
      <main
        class="py-10 px-4 sm:px-6 lg:px-8"
      >
        <Navigation />
        <CreateLogin />
      </main>
    </div>
  );
};

const EditLoginPage: Component = () => {
  return (
    <div
      class="min-h-screen bg-gray-1"
    >
      <main
        class="py-10 px-4 sm:px-6 lg:px-8"
      >
        <Navigation />
        <Suspense>
          <EditLogin />
        </Suspense>
      </main>
    </div>
  );
};

const LoginDetailPage: Component = () => {
  return (
    <div
      class="min-h-screen bg-gray-1"
    >
      <main
        class="py-10 px-4 sm:px-6 lg:px-8"
      >
        <Navigation />
        <Suspense>
          <LoginDetail />
        </Suspense>
      </main>
    </div>
  );
};

const SettingsPage: Component = () => {
  return (
    <div
      class="min-h-screen bg-gray-1"
    >
      <main
        class="py-10 px-4 sm:px-6 lg:px-8"
      >
        <Navigation />
        <Suspense>
          <Settings />
        </Suspense>
      </main>
    </div>
  );
};

const App: Component = () => {
  return (
    <Router>
      <Route
        component={Login}
        path="/login"
      />
      <Route
        component={TwoFactorVerification}
        path="/two-factor-verification"
      />
      <Route
        component={UsersPage}
        path="/"
      />
      <Route
        component={UsersPage}
        path="/users"
      />
      <Route
        component={CreateUserPage}
        path="/users/create"
      />
      <Route
        component={EditUserPage}
        path="/users/:id/edit"
      />
      <Route
        component={RolesPage}
        path="/roles"
      />
      <Route
        component={CreateRolePage}
        path="/roles/create"
      />
      <Route
        component={EditRolePage}
        path="/roles/:id/edit"
      />
      <Route
        component={LoginsPage}
        path="/logins"
      />
      <Route
        component={CreateLoginPage}
        path="/logins/create"
      />
      <Route
        component={LoginDetailPage}
        path="/logins/:id/detail"
      />
      <Route
        component={EditLoginPage}
        path="/logins/:id/edit"
      />
      <Route
        component={PasswordResetInit}
        path="/password-reset-init"
      />
      <Route
        component={PasswordReset}
        path="/password-reset/:code"
      />
      <Route
        component={FindUsername}
        path="/find-username"
      />
      <Route
        component={SettingsPage}
        path="/settings"
      />
    </Router>
  );
};

export default App;
