import styled from '@emotion/styled'

export const HomeHeroSection = styled.section`
  display: flex;
  justify-content: center;
  align-items: center;
  flex-direction: column;
  gap: 20px;
  width: 100%;
  margin: 0 30px 50px;
`

interface HomeDividerInterface {
  dividerColor: string
}

export const HomeDivider = styled.hr<HomeDividerInterface>`
  width: clamp(300px, 80vw, 800px);
  height: 3px;
  background-color: ${(_) => _.dividerColor};
`

// export const MainTodos = styled.article`
//   display: flex;
//   justify-content: center;
//   align-items: center;
//   flex-direction: column;
//   row-gap: 50px;
// `;

// export const TodosCarousel = styled.div`
//   display: flex;
//   justify-content: center;
//   align-items: center;
//   flex-direction: row;
//   column-gap: 20px;
// `;

export const TodoCard = styled.div`
  position: relative;
  padding: 10px 16px;
  border: 1px solid black;
  height: 80px;
  width: 100%;
  display: inline-block;
  overflow: hidden;
`

export const TodosContainer = styled.article`
  width: 100%;
  gap: 10px;
  columns: 280px;
`

export const TodoDataContainer = styled.div`
  display: flex;
  justify-content: start;
  align-items: start;
  flex-direction: column;
  gap: 10px;
`
export const TodoTitle = styled.h3`
  font-size: 1.5rem;
`

export const TodoDescription = styled.p`
  color: gray;
`

export const TodoCompleted = styled.button`
  background-color: white;
  width: 30px;
  height: 30px;
  display: inline-block;
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translate(0, -50%);
  z-index: 10;
`
