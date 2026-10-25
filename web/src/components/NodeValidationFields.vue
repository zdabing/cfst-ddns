<script setup lang="ts">
import type { NodeValidationConfig } from '@/api/types'
import FormItem from '@/components/FormItem.vue'
import NumInput from '@/components/NumInput.vue'
import SettingRow from '@/components/SettingRow.vue'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'

const form = defineModel<NodeValidationConfig>({ required: true })
</script>

<template>
  <div class="grid gap-4">
    <div class="rounded-md border">
      <SettingRow :label="$t('tasks.nodeValidation.enable')" :description="$t('tasks.nodeValidation.description')">
        <Switch v-model="form.enabled" />
      </SettingRow>
    </div>
    <template v-if="form.enabled">
      <p class="text-muted-foreground text-xs">{{ $t('tasks.nodeValidation.fileHelp') }}</p>
      <div class="grid gap-4 sm:grid-cols-2">
        <FormItem :label="$t('tasks.nodeValidation.mihomoPath')">
          <Input v-model="form.mihomoPath" placeholder="/usr/bin/mihomo" class="font-mono" />
        </FormItem>
        <FormItem :label="$t('tasks.nodeValidation.nodeFile')">
          <Input v-model="form.nodeFile" placeholder="/data/xhttp-node.json" class="font-mono" />
        </FormItem>
        <FormItem :label="$t('tasks.nodeValidation.testUrl')">
          <Input v-model="form.testUrl" type="url" placeholder="https://www.gstatic.com/generate_204" />
        </FormItem>
        <FormItem :label="$t('tasks.nodeValidation.expectedStatus')">
          <NumInput v-model="form.expectedStatus" :min="200" :max="299" />
        </FormItem>
        <FormItem :label="$t('tasks.nodeValidation.timeout')">
          <NumInput v-model="form.timeoutMs" :min="1000" :max="30000" suffix="ms" />
        </FormItem>
        <FormItem :label="$t('tasks.nodeValidation.maxCandidates')" :help="$t('tasks.nodeValidation.limitHelp')">
          <NumInput v-model="form.maxCandidates" :min="1" :max="100" />
        </FormItem>
        <FormItem :label="$t('tasks.nodeValidation.nameserver')" :help="$t('tasks.nodeValidation.dnsHelp')">
          <Input v-model="form.nameserver" placeholder="system" />
        </FormItem>
        <FormItem :label="$t('tasks.nodeValidation.interface')" :help="$t('tasks.nodeValidation.interfaceHelp')">
          <Input v-model="form.interfaceName" placeholder="pppoe-wan" />
        </FormItem>
      </div>
      <p class="text-muted-foreground text-xs">{{ $t('tasks.nodeValidation.keepHelp') }}</p>
    </template>
  </div>
</template>
