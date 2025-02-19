import styled from '@emotion/styled'

export const HomeHeroSection = styled.section`
  display: flex;
  justify-content: center;
  align-items: center;
  flex-direction: column;
  gap: 20px;
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
  border: 1px solid black;
  height: clamp(200px, 10em, 700px);
  /* width: 250px; */
  width: 300px;
  display: inline-block;
  overflow: hidden;
`

export const TodosContainer = styled.article`
  display: flex;
  justify-content: center;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
  column-count: 4;
`
