import { LoaderFunction } from "@remix-run/node";
import { authenticate } from "~/cognito.server";

export const loader: LoaderFunction = async ({ request }) => {
  // console.log({ url: request.url, headers: request.headers });

  return authenticate({ request });
};
