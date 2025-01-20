import { Component } from 'solid-js';
import { Router, Route } from '@solidjs/router';
import Login from './pages/Login';

const App: Component = () => {
  return (
    <Router>
      <Route path="/" component={Login} />
      <Route path="/login" component={Login} />
    </Router>
  );
};

export default App;
