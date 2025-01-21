import { Component } from 'solid-js';
import { Router, Route } from '@solidjs/router';
import Login from './pages/Login';
import Users from './pages/Users';
import CreateUser from './pages/CreateUser';
import EditUser from './pages/EditUser';

const App: Component = () => {
  return (
    <Router>
      <Route path="/" component={Login} />
      <Route path="/users" component={Users} />
      <Route path="/users/create" component={CreateUser} />
      <Route path="/users/:id/edit" component={EditUser} />
    </Router>
  );
};

export default App;
