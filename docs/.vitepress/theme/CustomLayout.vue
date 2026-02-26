<template>
  <Layout>
    <template #home-hero-after>
      <div class="hero-graphic-container">
        <HeroGraphic />
      </div>
    </template>
  </Layout>
</template>

<script setup>
import DefaultTheme from 'vitepress/theme'
import HeroGraphic from './HeroGraphic.vue'

const { Layout } = DefaultTheme
</script>

<style scoped>
.hero-graphic-container {
  max-width: 1200px;
  margin: 32px auto 0;
  padding: 0 24px;
}
</style>
