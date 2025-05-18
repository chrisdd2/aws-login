<script setup>
import { nextTick, ref } from 'vue';
import { useApi } from '../useApi';
let somevalue = ref(0);
const myvalue = ref(false)
const {isFetching, error, data} = useApi("auth/redirect_url").get().json()
async function increment(){
    somevalue.value +=1
    myvalue.value = !myvalue.value
}
</script>

<template>
    <div>
        <div>Main</div>
        <div>{{ somevalue }}</div>
        <button @click="increment">hi</button>
        <div v-if="myvalue">hello</div>
        <div v-else>not hello</div>
        <button @click="increment">hi</button>
        <div v-if="data">
            <p>{{ data.redirect_url }}</p>
        </div>
        <div v-else>
            <div>error: {{ error }}</div>
            <div>isFetching {{ isFetching }}</div>
            <div>data: {{ data }}</div>
        </div>
    </div>
</template>