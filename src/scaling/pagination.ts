/**
 * API Pagination Helper — cursor and offset-based pagination for large result sets
 * 
 * Supports two modes:
 * - Offset/limit: ?page=1&limit=50 (simple, good for browsing)
 * - Cursor-based: ?cursor=abc&limit=50 (efficient for large datasets, no skipping)
 * 
 * Default limit: 50, max limit: 200
 */

export interface PaginationParams {
  page: number;
  limit: number;
  offset: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasMore: boolean;
  };
}

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

/**
 * Extract pagination params from Express request query
 */
export function parsePagination(query: any): PaginationParams {
  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const rawLimit = parseInt(query.limit, 10) || DEFAULT_LIMIT;
  const limit = Math.min(Math.max(1, rawLimit), MAX_LIMIT);
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

/**
 * Apply pagination to an array of items
 */
export function paginate<T>(items: T[], params: PaginationParams): PaginatedResponse<T> {
  const total = items.length;
  const totalPages = Math.ceil(total / params.limit) || 1;
  const paged = items.slice(params.offset, params.offset + params.limit);

  return {
    items: paged,
    pagination: {
      page: params.page,
      limit: params.limit,
      total,
      totalPages,
      hasMore: params.page < totalPages,
    },
  };
}

/**
 * Apply pagination to a Map (converts values to array first)
 */
export function paginateMap<K, V>(map: Map<K, V>, params: PaginationParams): PaginatedResponse<V> {
  const values = Array.from(map.values());
  return paginate(values, params);
}
