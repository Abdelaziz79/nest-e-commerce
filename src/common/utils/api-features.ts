// src/common/utils/api-features.ts

import { Query, FilterQuery } from 'mongoose';

export interface PaginationOptions {
  page?: number;
  limit?: number;
  maxLimit?: number;
}

export interface SortOptions {
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  defaultSort?: Record<string, 1 | -1>;
}

export interface SearchOptions {
  searchFields?: string[];
  searchTerm?: string;
}

export interface FilterOptions {
  [key: string]: any;
}

export interface ApiFeatureOptions {
  pagination?: PaginationOptions;
  sort?: SortOptions;
  search?: SearchOptions;
  filters?: FilterOptions;
  select?: string;
}

export class ApiFeatures<T> {
  private query: Query<T[], T>;
  private queryOptions: ApiFeatureOptions;
  private countFilter: FilterQuery<T>;

  constructor(query: Query<T[], T>, options: ApiFeatureOptions = {}) {
    this.query = query;
    this.queryOptions = options;
    this.countFilter = query.getFilter();
  }

  /**
   * Apply text search
   */
  search(): this {
    const { search } = this.queryOptions;

    if (search?.searchTerm) {
      if (search.searchFields && search.searchFields.length > 0) {
        // Use regex search on specific fields
        const searchConditions = search.searchFields.map((field) => ({
          [field]: { $regex: search.searchTerm, $options: 'i' },
        }));

        const searchFilter = { $or: searchConditions } as any;
        this.query = this.query.find(searchFilter);
        this.countFilter = { ...this.countFilter, ...searchFilter };
      } else {
        // Use MongoDB text search (requires text index)
        const textSearchFilter = {
          $text: { $search: search.searchTerm },
        } as any;
        this.query = this.query.find(textSearchFilter);
        this.countFilter = { ...this.countFilter, ...textSearchFilter };
      }
    }

    return this;
  }

  /**
   * Apply filters
   */
  filter(): this {
    if (this.queryOptions.filters) {
      const filters = { ...this.queryOptions.filters };

      // Remove pagination/sort params if accidentally passed
      delete filters.page;
      delete filters.limit;
      delete filters.sortBy;
      delete filters.sortOrder;
      delete filters.search;

      this.query = this.query.find(filters);
      this.countFilter = { ...this.countFilter, ...filters };
    }

    return this;
  }

  /**
   * Apply sorting
   */
  sort(): this {
    const { sort } = this.queryOptions;

    if (sort?.sortBy) {
      const sortOrder = sort.sortOrder === 'desc' ? -1 : 1;
      this.query = this.query.sort({ [sort.sortBy]: sortOrder });
    } else if (sort?.defaultSort) {
      this.query = this.query.sort(sort.defaultSort);
    } else {
      // Default sort by creation date
      this.query = this.query.sort({ createdAt: -1 });
    }

    return this;
  }

  /**
   * Apply field selection
   */
  select(): this {
    if (this.queryOptions.select) {
      this.query = this.query.select(this.queryOptions.select);
    }

    return this;
  }

  /**
   * Apply pagination
   */
  paginate(): this {
    const { pagination } = this.queryOptions;

    if (pagination) {
      const page = Math.max(1, pagination.page || 1);
      const maxLimit = pagination.maxLimit || 100;
      const limit = Math.min(pagination.limit || 10, maxLimit);
      const skip = (page - 1) * limit;

      this.query = this.query.skip(skip).limit(limit);
    }

    return this;
  }

  /**
   * Execute query and return paginated result
   */
  async execute(): Promise<{
    data: T[];
    pagination: {
      total: number;
      page: number;
      limit: number;
      totalPages: number;
      hasNextPage: boolean;
      hasPrevPage: boolean;
    };
  }> {
    const { pagination } = this.queryOptions;
    const page = Math.max(1, pagination?.page || 1);
    const maxLimit = pagination?.maxLimit || 100;
    const limit = Math.min(pagination?.limit || 10, maxLimit);

    const [data, total] = await Promise.all([
      this.query.exec(),
      this.query.model.countDocuments(this.countFilter).exec(),
    ]);

    const totalPages = Math.ceil(total / limit);

    return {
      data,
      pagination: {
        total,
        page,
        limit,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }

  /**
   * Execute query without pagination
   */
  async executeWithoutPagination(): Promise<T[]> {
    return this.query.exec();
  }

  /**
   * Get count only
   */
  async count(): Promise<number> {
    return this.query.model.countDocuments(this.countFilter).exec();
  }
}

/**
 * Helper function to create ApiFeatures instance
 */
export function createApiFeatures<T>(
  query: Query<T[], T>,
  options: ApiFeatureOptions = {},
): ApiFeatures<T> {
  return new ApiFeatures<T>(query, options);
}
