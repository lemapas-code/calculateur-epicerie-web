import { onRequestPost as __api_admin_action_js_onRequestPost } from "D:\\Script\\costco\\calculateur-epicerie-web\\functions\\api\\admin\\action.js"
import { onRequestGet as __api_admin_list_js_onRequestGet } from "D:\\Script\\costco\\calculateur-epicerie-web\\functions\\api\\admin\\list.js"
import { onRequestGet as __api_config_js_onRequestGet } from "D:\\Script\\costco\\calculateur-epicerie-web\\functions\\api\\config.js"
import { onRequestPost as __api_google_login_js_onRequestPost } from "D:\\Script\\costco\\calculateur-epicerie-web\\functions\\api\\google-login.js"
import { onRequestPost as __api_request_access_js_onRequestPost } from "D:\\Script\\costco\\calculateur-epicerie-web\\functions\\api\\request-access.js"
import { onRequest as __api_admin__middleware_js_onRequest } from "D:\\Script\\costco\\calculateur-epicerie-web\\functions\\api\\admin\\_middleware.js"
import { onRequest as __api_logout_js_onRequest } from "D:\\Script\\costco\\calculateur-epicerie-web\\functions\\api\\logout.js"
import { onRequest as ___middleware_js_onRequest } from "D:\\Script\\costco\\calculateur-epicerie-web\\functions\\_middleware.js"

export const routes = [
    {
      routePath: "/api/admin/action",
      mountPath: "/api/admin",
      method: "POST",
      middlewares: [],
      modules: [__api_admin_action_js_onRequestPost],
    },
  {
      routePath: "/api/admin/list",
      mountPath: "/api/admin",
      method: "GET",
      middlewares: [],
      modules: [__api_admin_list_js_onRequestGet],
    },
  {
      routePath: "/api/config",
      mountPath: "/api",
      method: "GET",
      middlewares: [],
      modules: [__api_config_js_onRequestGet],
    },
  {
      routePath: "/api/google-login",
      mountPath: "/api",
      method: "POST",
      middlewares: [],
      modules: [__api_google_login_js_onRequestPost],
    },
  {
      routePath: "/api/request-access",
      mountPath: "/api",
      method: "POST",
      middlewares: [],
      modules: [__api_request_access_js_onRequestPost],
    },
  {
      routePath: "/api/admin",
      mountPath: "/api/admin",
      method: "",
      middlewares: [__api_admin__middleware_js_onRequest],
      modules: [],
    },
  {
      routePath: "/api/logout",
      mountPath: "/api",
      method: "",
      middlewares: [],
      modules: [__api_logout_js_onRequest],
    },
  {
      routePath: "/",
      mountPath: "/",
      method: "",
      middlewares: [___middleware_js_onRequest],
      modules: [],
    },
  ]