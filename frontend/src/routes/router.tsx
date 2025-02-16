import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from '@tanstack/react-router'
import Navbar from '../components/Navbar'
import Footer from '../components/Footer'
import * as pages from '../pages'

const rootRoute = createRootRoute({
  notFoundComponent: () => {
    return <h1>Not found</h1>
  },
  component: () => {
    return (
      <>
        <Navbar />
        <main>
          <Outlet />
        </main>
        <Footer />
      </>
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
  path: '/auh/register',
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
