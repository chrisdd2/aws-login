<script setup>
import { useRoute, useRouter } from 'vue-router';
import { useApi } from '../useApi';
import { computed, watch, watchEffect } from 'vue';
import { useSessionStorage } from '@vueuse/core';

const route = useRoute()
const router = useRouter()
const backEndUrl = computed( () => {
    console.log(route.query)
    return `auth/callback?${new URLSearchParams(route.query).toString()}`
})
const {isFetching, error, data } = useApi(backEndUrl).get().json()
const store = useSessionStorage("access_token", { label: "",email:"",access_token:""})

if (store.value.access_token) {
    router.push({path : "/"})
}


watchEffect(() => {
    if (data.value) {
        store.value = data.value
    }
})


</script>

<template>
{{ route.query }} 
<div v-if="data && !error">
    <p>{{ data }}</p>
</div>
<div v-if="error">
    <p>{{ error }}</p>
</div>
<div>
    {{ store }}
</div>
</template>