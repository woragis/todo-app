import { useAppDispatch, useAppSelector } from '@/redux/hooks'
import { useParams } from '@tanstack/react-router'

export const useTodoModel = () => {
  const { todoId } = useParams({ from: '/todos/$todoId' })

  const dispatch = useAppDispatch()
  // dispatch(getTodo(todoId))

  const todo = useAppSelector((state) => state.todos.todos[0])

  return { todo }
}
