import { ReduxStatus } from './redux.types'

export enum PostVisibility {
  Visible = 'visible',
  Hidden = 'hidden',
  Private = 'private',
}

export interface Post {
  id: number
  title: string
  body: string
  author_id: string
  visibility: string
  created_at: string
  updated_at: string
}
export interface PostResponse {
  posts: Post
}

export interface PostsResponse {
  posts: Post[]
}

export interface PostsState {
  data: PostsResponse
  status: ReduxStatus
  error: string | null
}

export interface CreatePostRequest {
  title: string
  body: string
  visibility: PostVisibility
}

export type { CreatePostRequest as UpdatePostRequest }
