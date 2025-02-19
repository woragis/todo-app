import styled from '@emotion/styled'

import { ThemeButtonProps } from '@/types/themeButton.types'

export const ThemeButtonContainer = styled.div<ThemeButtonProps>`
  --ball-radius: 30px;
  --color: ${(_) => _.navbarColor};
  --background-color: ${(_) => _.navbarBackgroundColor};
  --shaded-color: ${(_) => _.navbarColor};
  --shaded-background-color: ${(_) => _.navbarBackgroundColor};
  background-color: none;
`

export const InvisibleInput = styled.input`
  transition: 500ms;
  display: none;

  &[type='checkbox']:checked + .display {
    /* background: #2c2c2f; */
  }
  &[type='checkbox']:checked + .display label {
    /* background: #1f1f21; */
    box-shadow: 10px 10px 30px rgba(0, 0, 0, 0.5) inset;
  }
  &[type='checkbox']:checked + .display label .circle {
    left: 100%;
    transform: translate(-110%, -50%);
    /* background: #2c2c2f; */
    box-shadow: 10px 10px 20px rgba(0, 0, 0, 0.5),
      -10px -10px 30px rgba(0, 0, 0, 0.5) inset;
  }
  &[type='checkbox']:checked + .display label .circle .sun {
    margin-top: 150%;
    opacity: 0;
  }
  &[type='checkbox']:checked + .display label .circle .moon {
    margin-top: 0%;
    opacity: 1;
  }
`

export const DisplayedDiv = styled.div`
  * {
    transition: 500ms;
  }

  width: 80px;
  height: 50px;
  display: flex;
  align-items: center;
  justify-content: center;
  /* background-color: var(--background-color); */
  background-color: none;
`

export const ThemeLabel = styled.label`
  width: 70px;
  height: 40px;
  border-radius: 999px;
  background: #f3f3f3;
  box-shadow: 10px 10px 30px rgba(0, 0, 0, 0.05) inset;
  cursor: pointer;
  position: relative;

  &:active .circle {
    width: 100px;
  }
`

export const ThemeCircle = styled.div`
  width: 30px;
  height: 30px;
  border-radius: 50%;
  background: white;
  box-shadow: 10px 10px 20px rgba(0, 0, 0, 0.05),
    -10px -10px 30px rgba(0, 0, 0, 0.05) inset;
  position: absolute;
  top: 50%;
  left: 0%;
  transform: translate(10%, -50%);
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
`

export const SunSvg = styled.svg`
  width: 18px;
  position: absolute;
  color: #ffd600;
  margin-top: 0%;
  opacity: 1;
`

export const MoonSvg = styled.svg`
  width: 16px;
  position: absolute;
  margin-top: -150%;
  color: white;
  opacity: 0;
`
