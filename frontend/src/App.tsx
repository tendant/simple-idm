import { Component, Suspense } from 'solid-js';
import { Router, Route } from '@solidjs/router';
import Login from './pages/Login';
import Users from './pages/Users';
import CreateUser from './pages/CreateUser';
import EditUser from './pages/EditUser';
import Roles from './pages/Roles';
import CreateRole from './pages/CreateRole';
import EditRole from './pages/EditRole';
import Navigation from './components/Navigation';

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

const App: Component = () => {
  return (
    <Router>
      <Route path="/login" component={Login} />
      <Route path="/" component={UsersPage} />
      <Route path="/users" component={UsersPage} />
      <Route path="/users/create" component={CreateUserPage} />
      <Route path="/users/:id/edit" component={EditUserPage} />
      <Route path="/roles" component={RolesPage} />
      <Route path="/roles/create" component={CreateRolePage} />
      <Route path="/roles/:uuid/edit" component={EditRolePage} />
    </Router>
  );
};

export default App;
