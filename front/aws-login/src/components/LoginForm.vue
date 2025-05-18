<template>
  <div class="github-login">
    <h2>Log in with GitHub</h2>
    <button @click="redirectToGitHub">
      <img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub" />
      Continue with GitHub
    </button>
  </div>
</template>

<script setup>
async function redirectToGitHub() {
  try {
    const response = await fetch('http://localhost:8080/api/auth/redirect_url')
    const data = await response.json()

    if (data.redirect_url) {
      window.location.href = data.redirect_url
    } else {
      console.error('GitHub URL not received')
    }
  } catch (error) {
    console.error('Error fetching GitHub auth URL:', error)
  }
}
</script>

<style scoped>
.github-login {
  text-align: center;
  margin-top: 100px;
}

button {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 0.75rem 1.5rem;
  background-color: black;
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 16px;
  cursor: pointer;
}

button img {
  width: 24px;
  height: 24px;
}
</style>
