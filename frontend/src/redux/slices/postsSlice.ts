import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import {
  createPostService,
  getPostService,
  getPostsService,
  updatePostService,
  deletePostService,
} from "../../api/services/postsService";
import {
  CreatePostRequest,
  PostResponse,
  PostsState,
  UpdatePostRequest,
} from "../../types/posts.types";

const initialState: PostsState = {
  data: {
    posts: [],
  },
  status: "idle",
  error: null,
};

export const getPosts = createAsyncThunk(
  "posts/getMany",
  async (token: string, { rejectWithValue }) => {
    try {
      const data = await getPostsService(token);
      return data;
    } catch (error: any) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to get posts"
      );
    }
  }
);

export const createPost = createAsyncThunk(
  "posts/create",
  async (
    payload: { token: string; post: CreatePostRequest },
    { rejectWithValue }
  ) => {
    try {
      const newPostId = await createPostService(payload.token, payload.post);
      return newPostId;
    } catch (error: any) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to create new post"
      );
    }
  }
);

export const getPost = createAsyncThunk(
  "posts/get",
  async (payload: { token: string; post_id: number }, { rejectWithValue }) => {
    try {
      const post = await getPostService(payload.token, payload.post_id);
      return post as PostResponse;
    } catch (error: any) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to delete post"
      );
    }
  }
);

export const updatePost = createAsyncThunk(
  "posts/update",
  async (
    payload: { token: string; post_id: number; post: UpdatePostRequest },
    { rejectWithValue }
  ) => {
    try {
      const post = await updatePostService(
        payload.token,
        payload.post_id,
        payload.post
      );
      return post as PostResponse;
    } catch (error: any) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to update post"
      );
    }
  }
);

export const deletePost = createAsyncThunk(
  "posts/delete",
  async (payload: { token: string; post_id: number }, { rejectWithValue }) => {
    try {
      const deleted = await deletePostService(payload.token, payload.post_id);
      return deleted as boolean;
    } catch (error: any) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to delete post"
      );
    }
  }
);

const postsSlice = createSlice({
  name: "posts",
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    builder

      // Get posts cases
      .addCase(getPosts.pending, (state) => {
        state.status = "loading";
        state.error = null;
      })
      .addCase(getPosts.fulfilled, (state, action) => {
        state.status = "succeeded";
        state.error = null;
        state.data = action.payload;
      })
      .addCase(getPosts.rejected, (state, action) => {
        state.status = "failed";
        state.error = (action.payload as string) || null;
      })

      // Create post cases
      .addCase(createPost.pending, (state) => {
        state.status = "loading";
        state.error = null;
      })
      .addCase(createPost.fulfilled, (state) => {
        state.status = "succeeded";
        state.error = null;
      })
      .addCase(createPost.rejected, (state, action) => {
        state.status = "failed";
        state.error = (action.payload as string) || null;
      })

      // Get post cases
      .addCase(getPost.pending, (state) => {
        state.status = "loading";
        state.error = null;
      })
      .addCase(getPost.fulfilled, (state) => {
        state.status = "succeeded";
        state.error = null;
      })
      .addCase(getPost.rejected, (state, action) => {
        state.status = "failed";
        state.error = (action.payload as string) || null;
      })

      // Update post cases
      .addCase(updatePost.pending, (state) => {
        state.status = "loading";
        state.error = null;
      })
      .addCase(updatePost.fulfilled, (state) => {
        state.status = "succeeded";
        state.error = null;
      })
      .addCase(updatePost.rejected, (state, action) => {
        state.status = "failed";
        state.error = (action.payload as string) || null;
      })

      // Delete post cases
      .addCase(deletePost.pending, (state) => {
        state.status = "loading";
        state.error = null;
      })
      .addCase(deletePost.fulfilled, (state) => {
        state.status = "succeeded";
        state.error = null;
      })
      .addCase(deletePost.rejected, (state, action) => {
        state.status = "failed";
        state.error = (action.payload as string) || null;
      });
  },
});

export const {} = postsSlice.actions;
export default postsSlice.reducer;
