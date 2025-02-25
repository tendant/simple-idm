import { Component, Suspense } from 'solid-js';
import { Router, Route } from '@solidjs/router';
import Login from './pages/Login';
import Register from './pages/Register';
import Users from './pages/Users';
import CreateUser from './pages/CreateUser';
import EditUser from './pages/EditUser';
import Roles from './pages/Roles';
import CreateRole from './pages/CreateRole';
import EditRole from './pages/EditRole';
import Navigation from './components/Navigation';
import PasswordResetInit from './pages/PasswordResetInit';
import PasswordReset from './pages/PasswordReset';
import Settings from './pages/Settings';
import FindUsername from './pages/FindUsername';

const UsersPage: Component = () => {
  return (
    <div class="min-h-screen bg-gray-1">
      <main class="py-10 px-4 sm:px-6 lg:px-8">
        <Navigation />
        <Users />
      </main>
    </div>
  );
};

const CreateUserPage: Component = () => {
  return (
    <div class="min-h-screen bg-gray-1">
      <main class="py-10 px-4 sm:px-6 lg:px-8">
        <Navigation />
        <CreateUser />
      </main>
    </div>
  );
};

const EditUserPage: Component = () => {
  return (
    <div class="min-h-screen bg-gray-1">
      <main class="py-10 px-4 sm:px-6 lg:px-8">
        <Navigation />
        <EditUser />
      </main>
    </div>
  );
};

const RolesPage: Component = () => {
  return (
    <div class="min-h-screen bg-gray-1">
      <main class="py-10 px-4 sm:px-6 lg:px-8">
        <Navigation />
        <Roles />
      </main>
    </div>
  );
};

const CreateRolePage: Component = () => {
  return (
    <div class="min-h-screen bg-gray-1">
      <main class="py-10 px-4 sm:px-6 lg:px-8">
        <Navigation />
        <CreateRole />
      </main>
    </div>
  );
};

const EditRolePage: Component = () => {
  return (
    <div class="min-h-screen bg-gray-1">
      <main class="py-10 px-4 sm:px-6 lg:px-8">
        <Navigation />
        <Suspense>
          <EditRole />
        </Suspense>
      </main>
    </div>
  );
};

const SettingsPage: Component = () => {
  return (
    <div class="min-h-screen bg-gray-1">
      <main class="py-10 px-4 sm:px-6 lg:px-8">
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
      <Route path="/login" component={Login} />
      <Route path="/register" component={Register} />
      <Route path="/" component={UsersPage} />
      <Route path="/users" component={UsersPage} />
      <Route path="/users/create" component={CreateUserPage} />
      <Route path="/users/:id/edit" component={EditUserPage} />
      <Route path="/roles" component={RolesPage} />
      <Route path="/roles/create" component={CreateRolePage} />
      <Route path="/roles/:id/edit" component={EditRolePage} />
      <Route path="/password-reset-init" component={PasswordResetInit} />
      <Route path="/password-reset/:code" component={PasswordReset} />
      <Route path="/find-username" component={FindUsername} />
      <Route path="/settings" component={SettingsPage} />
    </Router>
  );
};

export default App;
