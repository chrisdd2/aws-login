import { useState, useEffect } from 'react';
export interface UseFetchOptions extends Omit<RequestInit,"signal">{
    queryParams?: string
}

export const useFetch = <T>(url: string, fetchOptions?:UseFetchOptions) => {
    const [data, setData] = useState({} as T);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const controller = new AbortController()
        fetch(url,{...fetchOptions,signal: controller.signal})
            .then(response => {
                if (!response.ok) {
                    throw Error('could not fetch the data for that resource');
                }
                return response.json();
            })
            .then(data => {
                setIsLoading(false);
                setData(data);
                setError(null);
            })
            .catch(err => {
                setIsLoading(false);
                setError(err.message);
            })
        return () => {
            if (isLoading)
                controller.abort("cancelled cause url changed")
        }
    }, [url])

    return { data, isLoading, error };
}
