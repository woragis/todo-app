import { useLocation } from '@tanstack/react-router'
export const useNotFoundModel = () => {
  const pageUrl = useLocation()
  return { pageUrl }
}
