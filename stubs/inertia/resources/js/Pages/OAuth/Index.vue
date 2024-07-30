<script setup>
import OAuthAppManager from '@/Pages/OAuth/Partials/OAuthAppManager.vue';
import AppLayout from '@/Layouts/AppLayout.vue';

defineProps({
    authorizedApps: Array,
    oauthApps: Array,
});
</script>

<template>
    <AppLayout title="OAuth Apps">
        <template #header>
            <h2 class="font-semibold text-xl text-gray-800 dark:text-gray-200 leading-tight">
                OAuth Apps
            </h2>
        </template>

        <div>
            <div class="max-w-7xl mx-auto py-10 sm:px-6 lg:px-8">
                <OAuthAppManager
                    :authorized-apps="authorizedApps"
                    :oauth-apps="oauthApps"
                />
            </div>
        </div>
    </AppLayout>
</template>
