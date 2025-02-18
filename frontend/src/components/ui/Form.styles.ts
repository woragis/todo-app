import styled from '@emotion/styled'

export const FormContainer = styled.section`
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100%;
  width: 100%;
  position: flex;
`

export const Form = styled.form`
  display: flex;
  justify-content: center;
  flex-direction: column;
  gap: 10px;
  align-items: center;
  min-height: 400px;
  max-height: 400px;
  padding: 50px;
  border-radius: 2rem;
  /* margin-top: -30px; */
  /* background-color: gray; */
  border: 1px solid gray;
  backdrop-filter: blur(5px);
  button,
  input {
    outline: none;
  }
`

export const Input = styled.input`
  padding: 20px 15px;
  height: 30px;
  font-weight: 500;
  font-size: 16px;
  background-color: #222;
  border: none;
  border-radius: 1rem;
`

export const Button = styled.button`
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 15px 15px;
  width: 120px;
  font-weight: 500;
  font-size: 1.2rem;
  background-color: #111;
  border: none;
  border-radius: 1rem;
`

export const ImgButton = styled.img`
  width: 30px;
  height: 30px;
`
