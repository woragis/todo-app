import { Link } from '@tanstack/react-router'

import { useHomeModel } from './model'
import {
  HomeDivider,
  HomeHeroSection,
  TodoCard,
  TodoCompleted,
  TodoDataContainer,
  TodoDescription,
  TodosContainer,
  TodoTitle,
} from './styles'

export const HomeView = ({
  todosTitle,
  todosNotFound,
  todos,
  isLoading,
  isError,
  dividerColor,
}: ReturnType<typeof useHomeModel>) => {
  if (!todos) {
    return (
      <HomeHeroSection>
        <h1>{todosNotFound}</h1>
        <HomeDivider dividerColor={dividerColor} />
      </HomeHeroSection>
    )
  }
  const todosComponent = todos.map((todo) => {
    return (
      <Link to={'todos/' + todo.id}>
        <TodoCard key={`listed_todo_${todo.id}`}>
          <TodoDataContainer>
            <TodoTitle>{todo.title}</TodoTitle>
            <TodoDescription>{todo.description}</TodoDescription>
          </TodoDataContainer>
          <TodoCompleted />
        </TodoCard>
      </Link>
    )
  })

  return (
    <HomeHeroSection>
      <h1>{todosTitle}</h1>
      <HomeDivider dividerColor={dividerColor} />
      {isLoading && <h1>Loading...</h1>}
      {isError && <h1>Error while loading todos...</h1>}
      <TodosContainer>{todosComponent}</TodosContainer>
    </HomeHeroSection>
  )
}
