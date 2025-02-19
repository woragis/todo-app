import styled from '@emotion/styled'

export const StyledTodo = styled.article`
  width: 100%;
  margin-top: -80px;
  min-height: 100vh;
  padding: 100px 80px 50px;
  display: grid;
  grid-template-rows: 80px 1fr;
  /* display: flex;
  justify-content: center;
  align-items: center;
  flex-direction: column; */
`

export const StyledTodoTitle = styled.input`
  font-size: 3rem;
  background-color: rgba(255, 255, 255, 0.1);
  padding: 20px 40px;
  border-radius: 40px;
  border: none;
  width: 100%;
  display: inline-block;
`

export const StyledTodoId = styled.span`
  display: inline-block;
  position: absolute;
  right: 50px;
  bottom: 0px;
  color: gray;
`

export const StyledTodoBody = styled.textarea`
  margin-top: 20px;
  font-size: 1.3rem;
  background-color: rgba(126, 126, 126, 0.1);
  padding: 20px 40px;
  border-radius: 20px;
  border: none;
  width: 100%;
`
