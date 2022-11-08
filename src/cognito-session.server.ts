import { createCookieSessionStorage, redirect } from "@remix-run/node";
import Debug from "debug";
import { safeEnv } from "./utils/safe-env";

const debug = Debug("features:cognito:client");

const sessionSecret = safeEnv("SESSION_SECRET");

export const sessionStorage = createCookieSessionStorage({
  cookie: {
    name: "__session",
    httpOnly: true,
    path: "/",
    sameSite: "lax",
    secrets: [sessionSecret],
    secure: process.env.NODE_ENV === "production",
  },
});

const USER_SESSION_KEY = "user";

export async function getSession(request: Request) {
  const cookie = request.headers.get("Cookie");
  return sessionStorage.getSession(cookie);
}

interface User {
  sub: string;
  email: string;
  nickname: string;
}

export async function getUser(request: Request): Promise<User | undefined> {
  const session = await getSession(request);
  const user = session.get(USER_SESSION_KEY);
  debug("getUser", user);
  return user;
}

export async function requireUser(request: Request) {
  const user = await getUser(request);
  if (user) return user;

  throw await logout(request);
}

export async function createUserSession({
  request,
  user,
  remember,
  redirectTo,
  headers = new Headers(),
}: {
  request: Request;
  user: any;
  remember: boolean;
  redirectTo: string;
  headers: Headers;
}) {
  const session = await getSession(request);
  session.set(USER_SESSION_KEY, user);

  headers.append(
    "Set-Cookie",
    await sessionStorage.commitSession(session, {
      maxAge: remember
        ? 60 * 60 * 24 * 7 // 7 days
        : undefined,
    })
  );

  return redirect(redirectTo, { headers });
}

export async function logout(request: Request) {
  const session = await getSession(request);

  return sessionStorage.destroySession(session);
}
