import invariant from "tiny-invariant";

export const safeEnv = (key: string) => {
  const value = process.env[key];
  invariant(value, `${key} must be set`);
  return value;
};
