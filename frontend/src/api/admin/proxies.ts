/**
 * Admin Proxies API endpoints
 * Handles proxy server management for administrators
 */

import { apiClient } from '../client'
import type {
  Proxy,
  ProxyAccountSummary,
  ProxyQualityCheckResult,
  CreateProxyRequest,
  UpdateProxyRequest,
  PaginatedResponse,
  AdminDataPayload,
  AdminDataImportResult
} from '@/types'

/**
 * List all proxies with pagination
 * @param page - Page number (default: 1)
 * @param pageSize - Items per page (default: 20)
 * @param filters - Optional filters
 * @returns Paginated list of proxies
 */
export async function list(
  page: number = 1,
  pageSize: number = 20,
  filters?: {
    protocol?: string
    status?: 'active' | 'inactive' | 'expired'
    search?: string
    sort_by?: string
    sort_order?: 'asc' | 'desc'
  },
  options?: {
    signal?: AbortSignal
  }
): Promise<PaginatedResponse<Proxy>> {
  const { data } = await apiClient.get<PaginatedResponse<Proxy>>('/admin/proxies', {
    params: {
      page,
      page_size: pageSize,
      ...filters
    },
    signal: options?.signal
  })
  return data
}

/**
 * Get all active proxies (without pagination)
 * @returns List of all active proxies
 */
export async function getAll(): Promise<Proxy[]> {
  const { data } = await apiClient.get<Proxy[]>('/admin/proxies/all')
  return data
}

/**
 * Get all active proxies with account count (sorted by creation time desc)
 * @returns List of all active proxies with account count
 */
export async function getAllWithCount(): Promise<Proxy[]> {
  const { data } = await apiClient.get<Proxy[]>('/admin/proxies/all', {
    params: { with_count: 'true' }
  })
  return data
}

/**
 * Get proxy by ID
 * @param id - Proxy ID
 * @returns Proxy details
 */
export async function getById(id: number): Promise<Proxy> {
  const { data } = await apiClient.get<Proxy>(`/admin/proxies/${id}`)
  return data
}

/**
 * Create new proxy
 * @param proxyData - Proxy data
 * @returns Created proxy
 */
export async function create(proxyData: CreateProxyRequest): Promise<Proxy> {
  const { data } = await apiClient.post<Proxy>('/admin/proxies', proxyData)
  return data
}

export interface NativeProxyPreview {
  name: string
  protocol: string
  server_hint?: string
  dependencies: number
  fingerprint: string
}

export async function previewNative(input: string): Promise<NativeProxyPreview[]> {
  const { data } = await apiClient.post<NativeProxyPreview[]>('/admin/proxies/native/preview', { input })
  return data
}

export interface NativeProxyStatus {
  id: number
  proxy_id: number
  status: string
  auto_start: boolean
  restart_count: number
  last_error_code?: string
  last_error_redacted?: string
  listen_host: string
  listen_port: number
}

export async function getNativeStatus(proxyId: number): Promise<NativeProxyStatus> {
  const { data } = await apiClient.get<NativeProxyStatus>(`/admin/proxies/${proxyId}/native`)
  return data
}

export async function startNative(runtimeId: number): Promise<void> {
  await apiClient.post(`/admin/proxies/native/${runtimeId}/start`)
}

export async function stopNative(runtimeId: number): Promise<void> {
  await apiClient.post(`/admin/proxies/native/${runtimeId}/stop`)
}

export interface NativeProxyCreateResult {
  proxy_id: number
  runtime_id: number
  status: string
}

export async function createNative(payload: {
  name?: string
  input: string
  fingerprint: string
  visibility: 'private' | 'public'
  fallback_mode: 'none' | 'proxy' | 'direct'
  backup_proxy_id?: number | null
}): Promise<NativeProxyCreateResult> {
  const { data } = await apiClient.post<NativeProxyCreateResult>('/admin/proxies/native', payload)
  return data
}

export async function createNativeBatch(payload: {
  input: string
  fingerprints: string[]
  visibility: 'private' | 'public'
  fallback_mode: 'none' | 'proxy' | 'direct'
  backup_proxy_id?: number | null
}): Promise<NativeProxyCreateResult[]> {
  const { data } = await apiClient.post<NativeProxyCreateResult[]>('/admin/proxies/native/batch', payload)
  return data
}

/**
 * Update proxy
 * @param id - Proxy ID
 * @param updates - Fields to update
 * @returns Updated proxy
 */
export async function update(id: number, updates: UpdateProxyRequest): Promise<Proxy> {
  const { data } = await apiClient.put<Proxy>(`/admin/proxies/${id}`, updates)
  return data
}

/**
 * Delete proxy
 * @param id - Proxy ID
 * @returns Success confirmation
 */
export async function deleteProxy(id: number): Promise<{ message: string }> {
  const { data } = await apiClient.delete<{ message: string }>(`/admin/proxies/${id}`)
  return data
}

/**
 * Toggle proxy status
 * @param id - Proxy ID
 * @param status - New status
 * @returns Updated proxy
 */
export async function toggleStatus(id: number, status: 'active' | 'inactive'): Promise<Proxy> {
  return update(id, { status })
}

/**
 * Test proxy connectivity
 * @param id - Proxy ID
 * @returns Test result with IP info
 */
export async function testProxy(id: number): Promise<{
  success: boolean
  message: string
  latency_ms?: number
  ip_address?: string
  city?: string
  region?: string
  country?: string
  country_code?: string
}> {
  const { data } = await apiClient.post<{
    success: boolean
    message: string
    latency_ms?: number
    ip_address?: string
    city?: string
    region?: string
    country?: string
    country_code?: string
  }>(`/admin/proxies/${id}/test`)
  return data
}

/**
 * Check proxy quality across common AI targets
 * @param id - Proxy ID
 * @returns Quality check result
 */
export async function checkProxyQuality(id: number): Promise<ProxyQualityCheckResult> {
  const { data } = await apiClient.post<ProxyQualityCheckResult>(`/admin/proxies/${id}/quality-check`)
  return data
}

/**
 * Get proxy usage statistics
 * @param id - Proxy ID
 * @returns Proxy usage statistics
 */
export async function getStats(id: number): Promise<{
  total_accounts: number
  active_accounts: number
  total_requests: number
  success_rate: number
  average_latency: number
}> {
  const { data } = await apiClient.get<{
    total_accounts: number
    active_accounts: number
    total_requests: number
    success_rate: number
    average_latency: number
  }>(`/admin/proxies/${id}/stats`)
  return data
}

/**
 * Get accounts using a proxy
 * @param id - Proxy ID
 * @returns List of accounts using the proxy
 */
export async function getProxyAccounts(id: number): Promise<ProxyAccountSummary[]> {
  const { data } = await apiClient.get<ProxyAccountSummary[]>(`/admin/proxies/${id}/accounts`)
  return data
}

/**
 * Batch create proxies
 * @param proxies - Array of proxy data to create
 * @returns Creation result with count of created and skipped
 */
export async function batchCreate(
  proxies: Array<{
    protocol: string
    host: string
    port: number
    username?: string
    password?: string
  }>
): Promise<{
  created: number
  skipped: number
}> {
  const { data } = await apiClient.post<{
    created: number
    skipped: number
  }>('/admin/proxies/batch', { proxies })
  return data
}

export async function batchDelete(ids: number[]): Promise<{
  deleted_ids: number[]
  skipped: Array<{ id: number; reason: string }>
}> {
  const { data } = await apiClient.post<{
    deleted_ids: number[]
    skipped: Array<{ id: number; reason: string }>
  }>('/admin/proxies/batch-delete', { ids })
  return data
}

export async function exportData(options?: {
  ids?: number[]
  filters?: {
    protocol?: string
    status?: 'active' | 'inactive' | 'expired'
    search?: string
    sort_by?: string
    sort_order?: 'asc' | 'desc'
  }
}): Promise<AdminDataPayload> {
  const params: Record<string, string> = {}
  if (options?.ids && options.ids.length > 0) {
    params.ids = options.ids.join(',')
  } else if (options?.filters) {
    const { protocol, status, search, sort_by, sort_order } = options.filters
    if (protocol) params.protocol = protocol
    if (status) params.status = status
    if (search) params.search = search
    if (sort_by) params.sort_by = sort_by
    if (sort_order) params.sort_order = sort_order
  }
  const { data } = await apiClient.get<AdminDataPayload>('/admin/proxies/data', { params })
  return data
}

export async function importData(payload: {
  data: AdminDataPayload
}): Promise<AdminDataImportResult> {
  const { data } = await apiClient.post<AdminDataImportResult>('/admin/proxies/data', payload)
  return data
}

export const proxiesAPI = {
  list,
  getAll,
  getAllWithCount,
  getById,
  create,
  previewNative,
  createNative,
  createNativeBatch,
  getNativeStatus,
  startNative,
  stopNative,
  update,
  delete: deleteProxy,
  toggleStatus,
  testProxy,
  checkProxyQuality,
  getStats,
  getProxyAccounts,
  batchCreate,
  batchDelete,
  exportData,
  importData
}

export default proxiesAPI
