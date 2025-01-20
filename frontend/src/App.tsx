import { Component } from 'solid-js';
import { Router, Routes, Route } from '@solidjs/router';
import Login from './pages/Login';

const App: Component = () => {
  return (
    <Router>
      <Routes>
        <Route path="/" component={Login} />
        <Route path="/login" component={Login} />
      </Routes>
    </Router>
  );
};

export default App;
