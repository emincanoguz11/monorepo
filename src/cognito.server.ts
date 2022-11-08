import { redirect, createCookie } from "@remix-run/node";
import Debug from "debug";
import invariant from "tiny-invariant";
import { safeEnv } from "~/utils/safe-env";
import { createUserSession } from "./cognito-session.server";
import { CognitoClient, CognitoToken } from "./features/cognito/client";

const debug = Debug("pano:cognito.server");

const sessionSecret = safeEnv("SESSION_SECRET");
const cognitoDomain = safeEnv("COGNITO_DOMAIN");
const cognitoClientId = safeEnv("COGNITO_CLIENT_ID");
const cognitoClientSecret = safeEnv("COGNITO_CLIENT_SECRET");
const cognitoClientCallback = safeEnv("COGNITO_CLIENT_CALLBACK");

const cognitoClient = new CognitoClient({
  domain: cognitoDomain,
  clientID: cognitoClientId,
  clientSecret: cognitoClientSecret,
  clientCallbackUri: cognitoClientCallback,
});

const cookieSettings = {
  maxAge: 60 * 60 * 30,
  secure: process.env.NODE_ENV === "production",
  secrets: [sessionSecret],
  httpOnly: true,
};

const cookieAccessToken = createCookie("cognitoAccessToken", cookieSettings);
const cookieIdToken = createCookie("cognitoIdToken", cookieSettings);
const cookieRefreshToken = createCookie("cognitoRefreshToken", cookieSettings);

interface AuthenticateProps {
  request: Request;
}

const parseQueryParams = (url: URL) => {
  return {
    code: url.searchParams.get("code"),
    redirectTo: encodeURIComponent(url.searchParams.get("redirectTo") || "/"),
    state: url.searchParams.get("state"),
  };
};

const setHeaders = async (headers: Headers, token: CognitoToken) => {
  headers.append(
    "Set-cookie",
    await cookieAccessToken.serialize({ access_token: token.accessToken })
  );
  headers.append(
    "Set-cookie",
    await cookieIdToken.serialize({ id_token: token.idToken })
  );
  headers.append(
    "Set-cookie",
    await cookieRefreshToken.serialize({ refresh_token: token.refreshToken })
  );
};

export async function authenticate({ request }: AuthenticateProps) {
  const url = new URL(request.url);
  const { code, redirectTo, state } = parseQueryParams(url);

  invariant(code, "code param is required");

  const headers = new Headers();

  const token = await cognitoClient.token(code);
  debug("initial token", token);
  if (token) {
    setHeaders(headers, token);
    const user = await cognitoClient.userInfo(token);
    invariant(user, "cannot fetch user info from cognito");

    debug("user", user);

    const finalRedirectTo = decodeURIComponent(state || redirectTo);
    console.log("finalRedirectTo :>> ", finalRedirectTo);
    return createUserSession({
      redirectTo: finalRedirectTo,
      headers,
      remember: true,
      request,
      user,
    });
  }

  //The url does not have a code, so this is the first time we are hitting the login page
  //First try to get a user from an access token saved as a cookie
  let user = await getUserInfoUsingCookie(request);
  if (!user) {
    const refreshedToken = await refreshAccessToken(request);
    debug("refreshedToken", refreshedToken);
    if (refreshedToken) {
      user = await cognitoClient.userInfo(refreshedToken);
      if (user) {
        setHeaders(headers, refreshedToken);
      }
    }

    if (!user) {
      //if we still have no user then send them to the cognito login page
      const uri = getLoginAddress();
      debug("login uri", uri);
      return redirect(uri);
    }
  }

  if (!user) {
    return redirect(`/login?redirect=${redirectTo}`);
  }

  if (user) {
    //TODO Persist the user in the session
    debug("This should be persisted in session: ", user);

    const finalRedirectTo = decodeURIComponent(state || redirectTo);
    console.log("finalRedirectTo :>> ", finalRedirectTo);
    return createUserSession({
      redirectTo: finalRedirectTo,
      headers,
      remember: true,
      request,
      user,
    });
  }
}

const objToQuery = (input: Record<string, string>) => {
  return Object.entries(input)
    .map(([key, value]) => `${key}=${value}`)
    .join("&");
};

const getLoginAddress = () => {
  const url = new URL(`https://${cognitoDomain}/login`);

  url.search = objToQuery({
    client_id: cognitoClientId,
    response_type: "code",
    scope: "email+openid",
    redirect_uri: cognitoClientCallback,
  });

  return url.toString();
};

//Does the user have a valid access token? If so, return the user info
async function getUserInfoUsingCookie(request: Request) {
  const cookieHeaders = request.headers.get("Cookie");
  if (!cookieHeaders) {
    return false;
  }

  const cookie = await cookieAccessToken.parse(cookieHeaders);
  if (cookie?.access_token) {
    return cognitoClient.userInfo(cookie.access_token);
  }

  return true;
}

async function refreshAccessToken(request: Request) {
  const cookieHeaders = request.headers.get("Cookie");
  if (!cookieHeaders) {
    return null;
  }

  const cookie = await cookieRefreshToken.parse(cookieHeaders);
  if (!cookie) {
    return null;
  }

  if (!cookie.refresh_token) {
    return null;
  }
  return cognitoClient.refreshToken(cookie.refresh_token);
}
