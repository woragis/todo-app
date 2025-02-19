import styled from '@emotion/styled'

import { LanguageOptionsContainerProps } from '@/types/languageSwitcher.types'

export const LanguageOptionsContainer = styled.details<LanguageOptionsContainerProps>`
  --color: ${(_) => _.color};
  color: var(--color);
  background-color: ${(_) => _.backgroundColor};
  height: fit-content;
  width: 200px;
  box-shadow: inset 0 0px 12px var(--color);
  border-radius: 15px;
  display: flex;
  justify-content: center;
  align-items: center;
  flex-direction: column;
  gap: 5px;
  position: relative;
`

export const LanguageButton = styled.summary`
  font-size: 20px;
  padding: 10px 15px;
  position: relative;
`

export const OptionsContainer = styled.div`
  position: absolute;
  bottom: -200%;
  background-color: black;
  overflow: visible;
  height: max-content;
`

export const StyledLanguageOption = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 5px 15px;
  font-size: 15px;
  width: 100%;
  border-radius: 10px;
  position: relative;

  &:hover {
    cursor: pointer;
  }

  &::before {
    content: '';
    position: absolute;
    top: -4px;
    left: 0;
    width: 100%;
    height: 2px;
    background-color: var(--color);
  }
`
