import { useFetchAuthed } from "@/hooks/use-auth";
import { useAuthToken, type AuthToken } from "@/hooks/use-token";
import { useEffect, useMemo } from "react";
import { useLocation, useNavigate, useSearchParams} from "react-router"

export function LoginCallback() {
    const [ params, _ ] = useSearchParams()
    const {setToken} = useAuthToken()
    const navigate = useNavigate()
    const {data,isLoading,error} = useFetchAuthed<AuthToken>("/api/auth/callback",{ queryParams: params.toString(),method:"GET"})

    useEffect( () => {
        if (!data || !data.access_token || error) return
        setToken(data)
        console.log({data,isLoading,error},"token")
    },[data,error,isLoading])
    useEffect( () => {
        console.log({data,isLoading,error},"navigate")
        if (data.access_token) navigate("/");
    }, [data])


    return <>
        { isLoading && <div>Loading</div>}
        { error && <div>Error loading [{error}]</div>}
    </>
}
export function Login() {
    const {data,isLoading,error} = useFetchAuthed<{redirect_url:string}>("/api/auth/redirect_url",{method:"GET"})

    useEffect( () => {
        if (!data || error) return
        // go to idp
        window.location.href = data.redirect_url
    },[data,isLoading,error])

    return <>
    <div>
        { isLoading && <div>Loading</div>}
        { error && <div>Error loading [{error}]</div>}
    </div>
    </>
}