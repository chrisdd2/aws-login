import { Outlet } from 'react-router'
import { AuthTokenCtx, createAuthToken } from './hooks/use-token'

function App() {
  const authToken = createAuthToken()

  return (
    <>
      <AuthTokenCtx.Provider value={authToken}>
        <div>
          {authToken.token.label}
        </div>
        <div>
          {authToken.token.email}
        </div>
        <Outlet></Outlet>
      </AuthTokenCtx.Provider>
    </>
  )
}

export default App
