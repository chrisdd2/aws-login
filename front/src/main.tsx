import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

import {
  createBrowserRouter,
  RouterProvider,
} from "react-router";
import { Accounts } from './components/Accounts.tsx';
import { Login, LoginCallback } from './components/Login.tsx';

const router = createBrowserRouter([
  {
    path: "/",
    element: <App/>,
    children: [
      {
        path: "accounts",
        element: <Accounts/>
      },
      {
        path: "oauth2/idpresponse",
        element: <LoginCallback/>
      },
      {
        path: "login",
        element: <Login/>,

      }
    ]
  },
])



createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router}></RouterProvider>
  </StrictMode>,
)
