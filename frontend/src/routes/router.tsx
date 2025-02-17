import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from '@tanstack/react-router'
import { ThemeProvider } from '@emotion/react'
import { useAppSelector } from '@/features/hooks'
import * as pages from '@/pages'
import { Footer } from '@/components'
import { Navbar } from '@/components'

const rootRoute = createRootRoute({
  notFoundComponent: () => {
    return <h1>Not found</h1>
  },
  component: () => {
    const theme = useAppSelector((state) => state.theme.colors)

    return (
      <ThemeProvider theme={theme}>
        <Navbar />
        <main>
          <Outlet />
        </main>
        <Footer />
      </ThemeProvider>
    )
  },
})

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: pages.Home,
})

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/auth/login',
  component: pages.Login,
})

const registerRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/auth/register',
  component: pages.Register,
})

const profileRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/profile',
  component: pages.Profile,
})

const todoRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'todos/$todoId',
  component: pages.Todo,
})

const routes = [indexRoute, profileRoute, todoRoute, registerRoute, loginRoute]
export const routeTree = rootRoute.addChildren(routes)

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}

export const router = createRouter({ routeTree })
