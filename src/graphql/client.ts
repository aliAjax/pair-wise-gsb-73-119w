import { ApolloClient, ApolloLink, InMemoryCache, Observable } from '@apollo/client/core'
import { loadState } from '@/services/repository'
import {
  activeControls,
  activeThreats,
  dashboardMetrics,
  evidenceIsExpired,
  isRetired,
} from '@/services/selectors'

const resolveOperation = (operationName: string): Record<string, unknown> => {
  const state = loadState()

  if (operationName === 'DashboardMetrics') {
    return { dashboardMetrics: dashboardMetrics(state) }
  }

  if (operationName === 'ThreatIndex') {
    return {
      threatIndex: activeThreats(state).map((threat) => ({
        id: threat.id,
        code: threat.code,
        title: threat.title,
        severity: threat.severity,
        status: threat.status,
        reviewStatus: threat.reviewStatus,
        componentCount: threat.componentIds.length,
        controlCount: threat.controlIds.length,
      })),
    }
  }

  if (operationName === 'ControlHealth') {
    const controls = activeControls(state)
    return {
      controlHealth: {
        total: controls.length,
        effective: controls.filter((control) => control.status === 'effective').length,
        degraded: controls.filter((control) => control.status === 'degraded').length,
        failed: controls.filter((control) => control.status === 'failed').length,
        missingEvidence: controls.filter((control) => {
          const evidence = control.evidenceIds
            .map((id) => state.evidence.find((item) => item.id === id))
            .filter((item) => item && !isRetired(item) && item.valid && !evidenceIsExpired(item))
          return evidence.length === 0
        }).length,
      },
    }
  }

  throw new Error(`未注册的 GraphQL 操作：${operationName}`)
}

const localLink = new ApolloLink(
  (operation) =>
    new Observable((observer) => {
      try {
        observer.next({ data: resolveOperation(operation.operationName) })
        observer.complete()
      } catch (error) {
        observer.error(error)
      }
    }),
)

export const apolloClient = new ApolloClient({
  link: localLink,
  cache: new InMemoryCache(),
  defaultOptions: {
    query: {
      fetchPolicy: 'no-cache',
    },
  },
})
