import { ref, computed } from 'vue'

const loadingStates = ref({})
const loadingCounters = ref({})

export function useLoadingState() {
  const startLoading = (key) => {
    if (!loadingCounters.value[key]) {
      loadingCounters.value[key] = 0
    }
    loadingCounters.value[key]++
    loadingStates.value[key] = true
  }
  
  const stopLoading = (key) => {
    if (loadingCounters.value[key] && loadingCounters.value[key] > 0) {
      loadingCounters.value[key]--
      if (loadingCounters.value[key] === 0) {
        loadingStates.value[key] = false
      }
    } else {
      loadingStates.value[key] = false
    }
  }
  
  const isLoading = (key) => {
    return loadingStates.value[key] === true
  }
  
  const isLoadingAny = computed(() => {
    return Object.values(loadingStates.value).some(v => v === true)
  })
  
  const resetLoading = (key) => {
    loadingStates.value[key] = false
    loadingCounters.value[key] = 0
  }
  
  const resetAllLoading = () => {
    loadingStates.value = {}
    loadingCounters.value = {}
  }
  
  const withLoading = async (key, asyncFn) => {
    startLoading(key)
    try {
      return await asyncFn()
    } finally {
      stopLoading(key)
    }
  }
  
  return {
    loadingStates,
    startLoading,
    stopLoading,
    isLoading,
    isLoadingAny,
    resetLoading,
    resetAllLoading,
    withLoading
  }
}

export default useLoadingState
