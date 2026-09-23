import assert from "node:assert/strict";
import test from "node:test";
import { getStoredRefreshToken, setStoredRefreshToken } from "../src/auth-storage.js";

function createStorage() {
  const store = new Map();

  return {
    getItem(key) {
      return store.has(key) ? store.get(key) : null;
    },
    setItem(key, value) {
      store.set(key, value);
    },
    removeItem(key) {
      store.delete(key);
    }
  };
}

test.afterEach(() => {
  delete global.window;
});

test("stores refresh tokens in localStorage for the compatibility flow", () => {
  const sessionStorage = createStorage();
  const localStorage = createStorage();
  global.window = { sessionStorage, localStorage };

  setStoredRefreshToken("refresh-1");

  assert.equal(getStoredRefreshToken(), "refresh-1");
  assert.equal(localStorage.getItem("blindpass_refresh_token"), "refresh-1");
  assert.equal(sessionStorage.getItem("blindpass_refresh_token"), null);
});

test("clears the stored refresh token when set to null", () => {
  const localStorage = createStorage();
  global.window = { localStorage };

  setStoredRefreshToken("refresh-1");
  setStoredRefreshToken(null);

  assert.equal(getStoredRefreshToken(), null);
  assert.equal(localStorage.getItem("blindpass_refresh_token"), null);
});
