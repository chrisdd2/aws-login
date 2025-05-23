import { useContext, createContext, useState, useEffect} from "react";

export interface AuthToken {
    access_token: string
    label: string
    email: string
}
interface AuthTokenContext {
    token: AuthToken
    setToken: (token:AuthToken) => void
}
export const AuthTokenCtx = createContext({} as AuthTokenContext)
export function useAuthToken(): AuthTokenContext  {
    return useContext(AuthTokenCtx)
}

export const createAuthToken = () => {
  const key = "auth"
  const token = sessionStorage.getItem(key)
  const [value, setValue] = useState((token?JSON.parse(token):{}) as AuthToken)

  useEffect(() => {
  },[])

  const updateFunc = (t: AuthToken) => {
    if (!t.access_token) return;
    sessionStorage.setItem(key,JSON.stringify(t))
    setValue(t)
  }
  return { token:value, setToken: updateFunc}
}