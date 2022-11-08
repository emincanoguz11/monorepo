import Debug from "debug";
const debug = Debug("features:cognito:client");

interface CognitoClientOptions {
  domain: string;
  clientID: string;
  clientSecret: string;
  clientCallbackUri: string;
}

export interface CognitoToken {
  readonly accessToken: string;
  readonly idToken: string;
  readonly refreshToken: string;
}

interface AWSCognitoTokenResponse {
  readonly access_token: string;
  readonly id_token: string;
  readonly refresh_token: string;
}

export class CognitoClient {
  public readonly options;

  constructor(options: CognitoClientOptions) {
    this.options = options;
  }

  async token(code: string) {
    debug("token: start fetching with client options", this.options);
    const { domain, clientID, clientSecret, clientCallbackUri } = this.options;
    const uri = `https://${domain}/oauth2/token`;

    const response = await fetch(uri, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientID,
        client_secret: clientSecret,
        redirect_uri: clientCallbackUri,
        code,
      }),
    });

    debug("token response raw", response);

    // if (response.status === 200) {
    //   return null;
    // }

    const json = (await response.json()) as AWSCognitoTokenResponse;
    debug("getToken response", json);

    return {
      accessToken: json.access_token,
      idToken: json.id_token,
      refreshToken: json.refresh_token,
    } as CognitoToken;
  }

  async userInfo(token: Pick<CognitoToken, "accessToken">) {
    debug("userInfo: start fetching with client options", this.options);
    const uri = `https://${this.options.domain}/oauth2/userInfo`;

    const response = await fetch(uri, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token.accessToken}`,
      },
    });

    if (response.status === 200) {
      return await response.json();
    } else {
      return null;
    }
  }

  async refreshToken(existingToken: string) {
    debug("token: start fetching with client options", this.options);
    const { domain, clientID, clientCallbackUri } = this.options;

    const uri = `https://${domain}/oauth2/token`;
    const body = {
      grant_type: "refresh_token",
      client_id: clientID,
      redirect_uri: clientCallbackUri,
      refresh_token: existingToken,
    };
    const response = await fetch(uri, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams(body),
    });

    if (response.status === 200) {
      return null;
    }

    const json = (await response.json()) as AWSCognitoTokenResponse;
    debug("refreshToken response", json);

    return {
      accessToken: json.access_token,
      idToken: json.id_token,
      refreshToken: json.refresh_token,
    } as CognitoToken;
  }
}
