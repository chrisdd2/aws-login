import { createFetch, useSessionStorage } from "@vueuse/core";



export const useApi = createFetch({
    baseUrl: `${import.meta.env.VITE_API_URL}/api` ,
    options: {
        beforeFetch({options}) {
            const token = useSessionStorage("access_token",{access_token:""});
            if (token.value.access_token) {
                options.headers = {Authorization: `Bearer ${token}`,...options.headers}
            }
            return { options}
        },
    }
})