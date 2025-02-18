import { useGetTodoByIdQuery } from '@/features/todos/apiSlice'
import { useParams } from '@tanstack/react-router'

export const useTodoModel = () => {
  const { todoId: id } = useParams({ from: '/todos/$todoId' })
  const { data, isLoading, isSuccess } = useGetTodoByIdQuery(id, { skip: !id })
  let todo = data?.data

  return { todo, isLoading, isSuccess }
}
