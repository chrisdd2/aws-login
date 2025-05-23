import { useFetch, type UseFetchOptions } from "./use-fetch"
import { useAuthToken } from "./use-token"

const removePrefix = (s:string,prefix:string)=> {
    if (s.startsWith(prefix)) return s.substring(prefix.length);
    return s
}
const removeSuffix = (s:string,suffix:string)=> {
    if (s.endsWith(suffix)) return s.substring(0,s.length - suffix.length);
    return s
}

export const useFetchAuthed = <T>(url:string, options?:UseFetchOptions) =>{
    const {token} = useAuthToken()

    const finalUrl = new URL(`${removeSuffix(import.meta.env.VITE_API_URL,"/")}/${removePrefix(url,"/")}`)
    if (options?.queryParams) finalUrl.search = options.queryParams

    const fetchOptions:RequestInit = {...options}
    if (token.access_token)
    fetchOptions.headers = { ...fetchOptions.headers,Authorization: `Bearer ${token.access_token}`}

    return useFetch<T>(finalUrl.toString(),options)
}