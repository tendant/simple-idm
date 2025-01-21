import { Component } from 'solid-js';
import { Router, Route } from '@solidjs/router';
import Login from './pages/Login';
import Users from './pages/Users';
import CreateUser from './pages/CreateUser';
import EditUser from './pages/EditUser';
import Roles from './pages/Roles';
import CreateRole from './pages/CreateRole';
import EditRole from './pages/EditRole';
import Navigation from './components/Navigation';

const ProtectedRoutes: Component = () => {
  return (
    <div class="min-h-screen bg-gray-1">
      <Navigation />
      <main class="py-10 px-4 sm:px-6 lg:px-8">
        <Route path="/" component={Users} />
        <Route path="/users" component={Users} />
        <Route path="/users/create" component={CreateUser} />
        <Route path="/users/:id/edit" component={EditUser} />
        <Route path="/roles" component={Roles} />
        <Route path="/roles/create" component={CreateRole} />
        <Route path="/roles/:uuid/edit" component={EditRole} />
      </main>
    </div>
  );
};

const App: Component = () => {
  return (
    <Router>
      <Route path="/login" component={Login} />
      <Route path="/*" component={ProtectedRoutes} />
    </Router>
  );
};

export default App;
