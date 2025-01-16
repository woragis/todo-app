import { useSelector } from "react-redux";
import { NavPages, Pages } from "../../types/router.types";
import { RootState } from "../../features/store";
import { useTranslation } from "react-i18next";
import { useAppDispatch } from "../../features/hooks";
import { useNavigate } from "react-router-dom";
import { logout } from "../../features/slices/authSlice";
import { useState } from "react";

export const useNavbarModel = () => {
  const { t } = useTranslation();
  const auth = useSelector((state: RootState) => state.auth);
  const themeColors = useSelector((state: RootState) => state.theme.colors);
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const useLogout = () => {
    dispatch(logout());
    navigate("/");
  };
  const [loginVisible, setLoginVisible] = useState<boolean>(false);
  const [registerVisible, setRegisterVisible] = useState<boolean>(false);

  const navLinks: NavPages[] = [{ title: t(Pages.Home), path: "" }];

  const unloggedLinks: NavPages[] = [
    {
      title: t("login.title"),
      path: "",
      onClick: () => {
        setLoginVisible((prevState) => !prevState);
      },
    },
    {
      title: t("register.title"),
      path: "",
      onClick: () => {
        setRegisterVisible((prevState) => !prevState);
      },
    },
  ];

  const loggedLinks: NavPages[] = [
    { title: t("profile.title"), path: Pages.Profile, onClick: () => {} },
    {
      title: t("logout.title"),
      path: "",
      onClick: () => {
        useLogout();
      },
    },
  ];

  const authLinks = auth.loggedIn ? loggedLinks : unloggedLinks;

  const navLogo = "";

  return {
    navLinks,
    authLinks,
    themeColors,
    navLogo,
    loginVisible,
    registerVisible,
  };
};
