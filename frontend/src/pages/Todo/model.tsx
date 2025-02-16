import { useParams } from '@tanstack/react-router'
import { useAppDispatch } from '../../redux/hooks'
import { getTodo } from '../../redux/slices/todosSlice'
import { RootState } from '../../redux/store'
import { useSelector } from 'react-redux'

export const useTodoModel = () => {
  const { todoId } = useParams({ from: '/todos/$todoId' })

  const dispatch = useAppDispatch()
  dispatch(getTodo(todoId))

  const todo = useSelector((state: RootState) => state.todos.currentTodo)

  return { todo }
}
