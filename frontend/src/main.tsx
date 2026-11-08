import React from 'react'
import ReactDOM from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import ErrorPage from './error-page';
import './index.css'
import Root from '@/pages/root';
import 'bootstrap/dist/css/bootstrap.min.css'
import routes from './routes';
import axios from 'axios';

// load the certificate service
import './services/certificateservice'

const router = createBrowserRouter([
  {
    path: "/",
    element: <Root />,
    errorElement: <ErrorPage />,
    children: routes
  }
]);

// initialize any libraries that need initialization
axios.defaults.validateStatus = function () {
  // only error for connection-related issues
  return true;
}

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
)
