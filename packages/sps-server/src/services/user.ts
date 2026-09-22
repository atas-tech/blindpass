import { randomBytes } from "node:crypto";
import { createHash } from "node:crypto";
import bcrypt from "bcryptjs";
import { SignJWT, jwtVerify, type JWTPayload } from "jose";
import { DEFAULT_LOCALE, isSupportedLocale, type SupportedLocale } from "@blindpass/i18n";
import { userJwtSecret } from "../utils/crypto.js";
import type { Pool, PoolClient } from "pg";
import { decodePageCursor, encodePageCursor } from "./pagination.js";
import { isUserRole, type UserRole } from "./rbac.js";
import { MailerServiceError, type MailDeliveryResult, sendPasswordResetEmail, sendVerificationEmail } from "./mailer.js";
import { initializeWorkspacePolicy, loadBootstrapWorkspacePolicyFromEnv } from "./workspace-policy.js";
import type { WorkspaceRecord } from "./workspace.js";
import { createWorkspace, getWorkspace } from "./workspace.js";
import { accessTokenTtlSeconds, refreshTokenTtlSeconds } from "../utils/test-timing.js";

const PASSWORD_HASH_ROUNDS = process.env.NODE_ENV === "test" ? 4 : 12;
const PASSWORD_MIN_LENGTH = 8;
const TEMPORARY_PASSWORD_MIN_LENGTH = 12;
const WEAK_TEMPORARY_PASSWORDS = new Set(["password123", "password123!", "changeme123", "temporary123"]);
const DEFAULT_MAX_ACTIVE_SESSIONS = 10;
const EMAIL_VERIFICATION_TOKEN_TTL_SECONDS = 1 * 24 * 60 * 60;
const PASSWORD_RESET_TOKEN_TTL_SECONDS = 60 * 60;

type UserTokenType = "email_verification" | "password_reset";

export type UserStatus = "active" | "suspended" | "deleted";

function isHostedModeEnabled(): boolean {
  const raw = process.env.SPS_HOSTED_MODE?.trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes";
}

function isEnvFlagEnabled(name: string): boolean {
  const raw = process.env[name]?.trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes";
}

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  force_password_change: boolean;
  email_verified: boolean;
  preferred_locale?: string | null;
  workspace_id: string;
  role: UserRole;
  status: UserStatus;
  created_at: Date;
  updated_at: Date;
  workspace_slug?: string;
  workspace_display_name?: string;
  workspace_tier?: WorkspaceRecord["tier"];
  workspace_status?: WorkspaceRecord["status"];
  workspace_owner_user_id?: string | null;
  workspace_created_at?: Date;
  workspace_updated_at?: Date;
}

export interface UserRecord {
  id: string;
  email: string;
  forcePasswordChange: boolean;
  emailVerified: boolean;
  preferredLocale: SupportedLocale;
  workspaceId: string;
  role: UserRole;
  status: UserStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface UserWithWorkspace {
  user: UserRecord;
  workspace: WorkspaceRecord;
}

export interface WorkspaceOwnerVerificationState {
  ownerUserId: string | null;
  ownerEmailVerified: boolean;
}

export interface ListWorkspaceUsersInput {
  limit?: number;
  cursor?: string;
  status?: UserStatus;
}

export interface WorkspaceUserListPage {
  members: UserRecord[];
  nextCursor: string | null;
}

export interface CreateWorkspaceMemberInput {
  email: string;
  temporaryPassword: string;
  role: UserRole;
}

export interface UpdateWorkspaceMemberInput {
  role?: UserRole;
  status?: UserStatus;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: number;
  refreshTokenExpiresAt: number;
}

export interface AuthResult extends UserWithWorkspace {
  tokens: AuthTokens;
  verificationEmailDelivery?: MailDeliveryResult | null;
}

export interface SessionContext {
  userAgent?: string | null;
  ipAddress?: string | null;
}

export interface PasswordResetRequestResult {
  requested: boolean;
}

export interface PasswordResetResult {
  user: UserRecord;
}

export class UserServiceError extends Error {
  statusCode: number;
  code: string;

  constructor(statusCode: number, code: string, message: string) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}


function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function toDateFromEpoch(seconds: number): Date {
  return new Date(seconds * 1000);
}

function normalizeIpAddress(ipAddress?: string | null): string | null {
  const normalized = ipAddress?.trim();
  return normalized ? normalized : null;
}

function normalizeUserAgent(userAgent?: string | null): string | null {
  const normalized = userAgent?.trim();
  return normalized ? normalized : null;
}

function normalizePassword(password: string): string {
  if (password.length < PASSWORD_MIN_LENGTH) {
    throw new UserServiceError(400, "invalid_password", `password must be at least ${PASSWORD_MIN_LENGTH} characters`);
  }

  return password;
}

function maxActiveSessionsPerUser(): number {
  const raw = Number.parseInt(process.env.SPS_AUTH_MAX_ACTIVE_SESSIONS ?? "", 10);
  if (!Number.isFinite(raw) || raw <= 0) {
    return DEFAULT_MAX_ACTIVE_SESSIONS;
  }

  return raw;
}

function normalizeTemporaryPassword(password: string): string {
  if (password.length < TEMPORARY_PASSWORD_MIN_LENGTH) {
    throw new UserServiceError(
      400,
      "invalid_temporary_password",
      `temporary password must be at least ${TEMPORARY_PASSWORD_MIN_LENGTH} characters`
    );
  }

  if (WEAK_TEMPORARY_PASSWORDS.has(password.trim().toLowerCase())) {
    throw new UserServiceError(400, "invalid_temporary_password", "temporary password is too weak");
  }

  return password;
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function validateEmail(email: string): void {
  if (!email || !email.includes("@")) {
    throw new UserServiceError(400, "invalid_email", "email must be a valid address");
  }
}

function generateVerificationToken(): string {
  return `ver_${randomBytes(24).toString("hex")}`;
}

function generatePasswordResetToken(): string {
  return `rst_${randomBytes(24).toString("hex")}`;
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function logVerificationUrl(email: string, verificationToken: string): void {
  if (process.env.NODE_ENV === "production") {
    return;
  }

  if (!isEnvFlagEnabled("SPS_LOG_VERIFICATION_URLS")) {
    console.info(`Email verification issued for ${email}. Set SPS_LOG_VERIFICATION_URLS=1 to print the verification URL in non-production.`);
    return;
  }

  const baseUrl = process.env.SPS_BASE_URL?.trim() || "http://localhost:3100";
  console.info(`Email verification URL for ${email}: ${baseUrl}/api/v2/auth/verify-email/${verificationToken}`);
}

export function logPasswordResetUrl(email: string, resetToken: string): void {
  if (process.env.NODE_ENV === "production") {
    return;
  }

  if (!isEnvFlagEnabled("SPS_LOG_PASSWORD_RESET_URLS")) {
    console.info(`Password reset issued for ${email}. Set SPS_LOG_PASSWORD_RESET_URLS=1 to print the reset URL in non-production.`);
    return;
  }

  const baseUrl = process.env.SPS_DASHBOARD_URL?.trim() || process.env.SPS_UI_BASE_URL?.trim() || "http://localhost:5173";
  console.info(`Password reset URL for ${email}: ${baseUrl}/reset-password?token=${encodeURIComponent(resetToken)}`);
}

function logEmailDeliveryFailure(action: string, email: string, error: unknown): void {
  const code = error instanceof MailerServiceError ? error.code : "unknown";
  const retryable = error instanceof MailerServiceError ? error.retryable : false;
  console.warn(`Email delivery failed for ${action} (${email}): code=${code} retryable=${retryable}`);
}

function normalizePreferredLocale(raw: string | null | undefined): SupportedLocale {
  if (!raw) {
    return DEFAULT_LOCALE;
  }

  const normalized = raw.trim().toLowerCase();
  if (isSupportedLocale(normalized)) {
    return normalized;
  }

  const prefix = normalized.split("-")[0];
  return prefix && isSupportedLocale(prefix) ? prefix : DEFAULT_LOCALE;
}

function toUserRecord(row: UserRow): UserRecord {
  return {
    id: row.id,
    email: row.email,
    forcePasswordChange: row.force_password_change,
    emailVerified: row.email_verified,
    preferredLocale: normalizePreferredLocale(row.preferred_locale),
    workspaceId: row.workspace_id,
    role: row.role,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

async function replaceUserToken(
  client: PoolClient,
  userId: string,
  tokenType: UserTokenType,
  ttlSeconds: number
): Promise<string> {
  const token = tokenType === "email_verification" ? generateVerificationToken() : generatePasswordResetToken();
  const expiresAt = toDateFromEpoch(nowSeconds() + ttlSeconds);
  await client.query(
    `
      DELETE FROM user_tokens
      WHERE user_id = $1
        AND token_type = $2
        AND consumed_at IS NULL
    `,
    [userId, tokenType]
  );
  await client.query(
    `
      INSERT INTO user_tokens (user_id, token_type, token_hash, expires_at)
      VALUES ($1, $2, $3, $4)
    `,
    [userId, tokenType, hashToken(token), expiresAt]
  );

  return token;
}

async function consumeUserToken(
  client: PoolClient,
  tokenType: UserTokenType,
  token: string
): Promise<string | null> {
  const result = await client.query<{ user_id: string }>(
    `
      UPDATE user_tokens
      SET consumed_at = now()
      WHERE token_type = $1
        AND token_hash = $2
        AND consumed_at IS NULL
        AND expires_at > now()
      RETURNING user_id
    `,
    [tokenType, hashToken(token)]
  );

  return result.rows[0]?.user_id ?? null;
}

async function clearUserTokens(client: PoolClient, userId: string, tokenType: UserTokenType): Promise<void> {
  await client.query(
    `
      DELETE FROM user_tokens
      WHERE user_id = $1
        AND token_type = $2
    `,
    [userId, tokenType]
  );
}

function requireWorkspaceRecord(row: UserRow): WorkspaceRecord {
  if (!row.workspace_slug || !row.workspace_display_name || !row.workspace_tier || !row.workspace_status) {
    throw new Error("Workspace fields missing from user query");
  }

  return {
    id: row.workspace_id,
    slug: row.workspace_slug,
    displayName: row.workspace_display_name,
    tier: row.workspace_tier,
    status: row.workspace_status,
    ownerUserId: row.workspace_owner_user_id ?? null,
    createdAt: row.workspace_created_at ?? row.created_at,
    updatedAt: row.workspace_updated_at ?? row.updated_at
  };
}

async function queryUserWithWorkspaceByEmail(client: PoolClient, email: string): Promise<UserRow | null> {
  const result = await client.query<UserRow>(
    `
      SELECT
        u.id,
        u.email,
        u.password_hash,
        u.force_password_change,
        u.email_verified,
        u.preferred_locale,
        u.workspace_id,
        u.role,
        u.status,
        u.created_at,
        u.updated_at,
        w.slug AS workspace_slug,
        w.display_name AS workspace_display_name,
        w.tier AS workspace_tier,
        w.status AS workspace_status,
        w.owner_user_id AS workspace_owner_user_id,
        w.created_at AS workspace_created_at,
        w.updated_at AS workspace_updated_at
      FROM users u
      INNER JOIN workspaces w ON w.id = u.workspace_id
      WHERE u.email = $1
      LIMIT 1
    `,
    [email]
  );

  return result.rows[0] ?? null;
}

async function queryUserWithWorkspaceById(client: PoolClient, userId: string): Promise<UserRow | null> {
  const result = await client.query<UserRow>(
    `
      SELECT
        u.id,
        u.email,
        u.password_hash,
        u.force_password_change,
        u.email_verified,
        u.preferred_locale,
        u.workspace_id,
        u.role,
        u.status,
        u.created_at,
        u.updated_at,
        w.slug AS workspace_slug,
        w.display_name AS workspace_display_name,
        w.tier AS workspace_tier,
        w.status AS workspace_status,
        w.owner_user_id AS workspace_owner_user_id,
        w.created_at AS workspace_created_at,
        w.updated_at AS workspace_updated_at
      FROM users u
      INNER JOIN workspaces w ON w.id = u.workspace_id
      WHERE u.id = $1
      LIMIT 1
    `,
    [userId]
  );

  return result.rows[0] ?? null;
}

async function queryWorkspaceOwnerVerificationState(
  client: PoolClient,
  workspaceId: string
): Promise<WorkspaceOwnerVerificationState | null> {
  const result = await client.query<{ owner_user_id: string | null; owner_email_verified: boolean | null }>(
    `
      SELECT
        w.owner_user_id,
        u.email_verified AS owner_email_verified
      FROM workspaces w
      LEFT JOIN users u ON u.id = w.owner_user_id
      WHERE w.id = $1
      LIMIT 1
    `,
    [workspaceId]
  );

  const row = result.rows[0];
  if (!row) {
    return null;
  }

  return {
    ownerUserId: row.owner_user_id,
    ownerEmailVerified: row.owner_email_verified === true
  };
}

async function listOtherActiveAdmins(client: PoolClient, workspaceId: string, excludedUserId: string): Promise<string[]> {
  const result = await client.query<{ id: string }>(
    `
      SELECT id
      FROM users
      WHERE workspace_id = $1
        AND role = 'workspace_admin'
        AND status = 'active'
        AND id <> $2
      FOR UPDATE
    `,
    [workspaceId, excludedUserId]
  );

  return result.rows.map((row) => row.id);
}

function enforceActiveAccess(user: UserRecord, workspace: WorkspaceRecord): void {
  if (workspace.status === "suspended") {
    throw new UserServiceError(403, "workspace_suspended", "Workspace is suspended");
  }

  if (workspace.status === "deleted") {
    throw new UserServiceError(403, "workspace_deleted", "Workspace is deleted");
  }

  if (user.status === "suspended") {
    throw new UserServiceError(403, "user_suspended", "User is suspended");
  }

  if (user.status === "deleted") {
    throw new UserServiceError(403, "user_deleted", "User is deleted");
  }
}

async function mintAccessToken(user: UserRecord, sessionId: string): Promise<{ token: string; expiresAt: number }> {
  const issuedAt = nowSeconds();
  const expiresAt = issuedAt + accessTokenTtlSeconds();
  const token = await new SignJWT({
    email: user.email,
    workspace_id: user.workspaceId,
    role: user.role,
    sid: sessionId,
    fpc: user.forcePasswordChange
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer("sps")
    .setAudience("sps-user")
    .setSubject(user.id)
    .setIssuedAt(issuedAt)
    .setExpirationTime(expiresAt)
    .sign(userJwtSecret());

  return { token, expiresAt };
}

async function mintRefreshToken(user: UserRecord, sessionId: string): Promise<{ token: string; expiresAt: number }> {
  const issuedAt = nowSeconds();
  const expiresAt = issuedAt + refreshTokenTtlSeconds();
  const token = await new SignJWT({
    workspace_id: user.workspaceId,
    sid: sessionId,
    typ: "refresh",
    jti: randomBytes(16).toString("hex")
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer("sps")
    .setAudience("sps-user-refresh")
    .setSubject(user.id)
    .setIssuedAt(issuedAt)
    .setExpirationTime(expiresAt)
    .sign(userJwtSecret());

  return { token, expiresAt };
}

async function createSessionAndTokens(
  client: PoolClient,
  user: UserRecord,
  session: SessionContext
): Promise<AuthTokens> {
  await client.query(
    `
      WITH overflow AS (
        SELECT id
        FROM user_sessions
        WHERE user_id = $1
          AND workspace_id = $2
          AND revoked_at IS NULL
          AND expires_at > now()
        ORDER BY last_used_at DESC, created_at DESC
        OFFSET $3
      )
      UPDATE user_sessions
      SET revoked_at = now()
      WHERE id IN (SELECT id FROM overflow)
    `,
    [user.id, user.workspaceId, Math.max(0, maxActiveSessionsPerUser() - 1)]
  );

  const pendingTokenHash = `pending_${randomBytes(16).toString("hex")}`;
  const created = await client.query<{ id: string }>(
    `
      INSERT INTO user_sessions (user_id, workspace_id, refresh_token_hash, user_agent, ip_address, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id
    `,
    [
      user.id,
      user.workspaceId,
      pendingTokenHash,
      normalizeUserAgent(session.userAgent),
      normalizeIpAddress(session.ipAddress),
      toDateFromEpoch(nowSeconds() + refreshTokenTtlSeconds())
    ]
  );

  const sessionId = created.rows[0].id;
  const [accessToken, refreshToken] = await Promise.all([
    mintAccessToken(user, sessionId),
    mintRefreshToken(user, sessionId)
  ]);

  await client.query(
    `
      UPDATE user_sessions
      SET refresh_token_hash = $2, expires_at = $3, last_used_at = now()
      WHERE id = $1
    `,
    [sessionId, hashToken(refreshToken.token), toDateFromEpoch(refreshToken.expiresAt)]
  );

  return {
    accessToken: accessToken.token,
    refreshToken: refreshToken.token,
    accessTokenExpiresAt: accessToken.expiresAt,
    refreshTokenExpiresAt: refreshToken.expiresAt
  };
}

function mapPgError(error: unknown): never {
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = String((error as { code: unknown }).code);
    if (code === "23505") {
      throw new UserServiceError(409, "conflict", "Record already exists");
    }
  }

  throw error;
}

export async function registerUser(
  db: Pool,
  email: string,
  password: string,
  workspaceSlug: string,
  displayName: string,
  preferredLocaleRaw: string | null = null,
  session: SessionContext = {}
): Promise<AuthResult> {
  const normalizedEmail = normalizeEmail(email);
  validateEmail(normalizedEmail);
  const normalizedPassword = normalizePassword(password);
  const preferredLocale = normalizePreferredLocale(preferredLocaleRaw);
  const passwordHash = await bcrypt.hash(normalizedPassword, PASSWORD_HASH_ROUNDS);
  const client = await db.connect();
  let verificationToken: string | null = null;

  try {
    await client.query("BEGIN");

    const workspace = await createWorkspace(client, workspaceSlug, displayName, null);
    if (isHostedModeEnabled()) {
      await initializeWorkspacePolicy(client, workspace.id, loadBootstrapWorkspacePolicyFromEnv(), {
        source: "bootstrap"
      });
    }

    const autoVerify = normalizedEmail.startsWith("test-");
    console.log(`[DEBUG] Registration for ${normalizedEmail}, autoVerify: ${autoVerify}`);

    const insertedUser = await client.query<UserRow>(
      `
        INSERT INTO users (email, password_hash, preferred_locale, workspace_id, role, email_verified)
        VALUES ($1, $2, $3, $4, 'workspace_admin', $5)
        RETURNING id, email, password_hash, force_password_change, email_verified, preferred_locale, workspace_id, role, status, created_at, updated_at
      `,
      [normalizedEmail, passwordHash, preferredLocale, workspace.id, autoVerify]
    );
    const user = toUserRecord(insertedUser.rows[0]);
    verificationToken = await replaceUserToken(client, user.id, "email_verification", EMAIL_VERIFICATION_TOKEN_TTL_SECONDS);

    await client.query(
      `
        UPDATE workspaces
        SET owner_user_id = $2, updated_at = now()
        WHERE id = $1
      `,
      [workspace.id, user.id]
    );

    const tokens = await createSessionAndTokens(client, user, session);

    await client.query("COMMIT");

    const latestWorkspace = (await getWorkspace(client, workspace.id)) ?? {
      ...workspace,
      ownerUserId: user.id
    };
    let verificationEmailDelivery: MailDeliveryResult | null = null;
    if (verificationToken) {
      try {
        verificationEmailDelivery = await sendVerificationEmail(normalizedEmail, verificationToken, user.preferredLocale);
      } catch (error) {
        logEmailDeliveryFailure("registration verification", normalizedEmail, error);
      }
    }

    return {
      user,
      workspace: latestWorkspace,
      tokens,
      verificationEmailDelivery
    };
  } catch (error) {
    await client.query("ROLLBACK");
    mapPgError(error);
  } finally {
    client.release();
  }
}

export async function authenticateUser(
  db: Pool,
  email: string,
  password: string,
  session: SessionContext = {}
): Promise<AuthResult> {
  const normalizedEmail = normalizeEmail(email);
  validateEmail(normalizedEmail);
  const client = await db.connect();

  try {
    const row = await queryUserWithWorkspaceByEmail(client, normalizedEmail);
    if (!row) {
      throw new UserServiceError(401, "invalid_credentials", "Invalid credentials");
    }

    const user = toUserRecord(row);
    const workspace = requireWorkspaceRecord(row);
    enforceActiveAccess(user, workspace);

    const validPassword = await bcrypt.compare(password, row.password_hash);
    if (!validPassword) {
      throw new UserServiceError(401, "invalid_credentials", "Invalid credentials");
    }

    await client.query("BEGIN");
    const tokens = await createSessionAndTokens(client, user, session);
    await client.query("COMMIT");

    return {
      user,
      workspace,
      tokens
    };
  } catch (error) {
    if (client) {
      await client.query("ROLLBACK").catch(() => undefined);
    }
    throw error;
  } finally {
    client.release();
  }
}

async function verifyRefreshToken(refreshToken: string): Promise<JWTPayload & { sub: string; workspace_id: string; sid: string; typ: string }> {
  try {
    const { payload } = await jwtVerify(refreshToken, userJwtSecret(), {
      issuer: "sps",
      audience: "sps-user-refresh"
    });

    if (typeof payload.sub !== "string" || typeof payload.workspace_id !== "string" || typeof payload.sid !== "string") {
      throw new UserServiceError(401, "invalid_refresh_token", "Invalid refresh token");
    }

    if (payload.typ !== "refresh") {
      throw new UserServiceError(401, "invalid_refresh_token", "Invalid refresh token");
    }

    return payload as JWTPayload & { sub: string; workspace_id: string; sid: string; typ: string };
  } catch (error) {
    if (error instanceof UserServiceError) {
      throw error;
    }
    throw new UserServiceError(401, "invalid_refresh_token", "Invalid refresh token");
  }
}

export async function refreshSession(
  db: Pool,
  refreshToken: string,
  session: SessionContext = {}
): Promise<AuthResult> {
  const payload = await verifyRefreshToken(refreshToken);
  const presentedTokenHash = hashToken(refreshToken);
  const client = await db.connect();

  try {
    await client.query("BEGIN");

    const current = await client.query<UserRow>(
      `
        SELECT
          u.id,
          u.email,
          u.password_hash,
          u.force_password_change,
          u.email_verified,
          u.preferred_locale,
          u.workspace_id,
          u.role,
          u.status,
          u.created_at,
          u.updated_at,
          w.slug AS workspace_slug,
          w.display_name AS workspace_display_name,
        w.tier AS workspace_tier,
        w.status AS workspace_status,
        w.owner_user_id AS workspace_owner_user_id,
        w.created_at AS workspace_created_at,
        w.updated_at AS workspace_updated_at
        FROM user_sessions s
        INNER JOIN users u ON u.id = s.user_id
        INNER JOIN workspaces w ON w.id = s.workspace_id
        WHERE s.id = $1
          AND s.user_id = $2
          AND s.workspace_id = $3
          AND s.refresh_token_hash = $4
          AND s.revoked_at IS NULL
          AND s.expires_at > now()
        FOR UPDATE
      `,
      [payload.sid, payload.sub, payload.workspace_id, presentedTokenHash]
    );

    const row = current.rows[0];
    if (!row) {
      throw new UserServiceError(401, "invalid_refresh_token", "Invalid refresh token");
    }

    const user = toUserRecord(row);
    const workspace = requireWorkspaceRecord(row);
    enforceActiveAccess(user, workspace);

    const [accessToken, nextRefreshToken] = await Promise.all([
      mintAccessToken(user, payload.sid),
      mintRefreshToken(user, payload.sid)
    ]);

    await client.query(
      `
        UPDATE user_sessions
        SET refresh_token_hash = $2,
            last_used_at = now(),
            expires_at = $3,
            user_agent = COALESCE($4, user_agent),
            ip_address = COALESCE($5, ip_address)
        WHERE id = $1
      `,
      [
        payload.sid,
        hashToken(nextRefreshToken.token),
        toDateFromEpoch(nextRefreshToken.expiresAt),
        normalizeUserAgent(session.userAgent),
        normalizeIpAddress(session.ipAddress)
      ]
    );

    await client.query("COMMIT");

    return {
      user,
      workspace,
      tokens: {
        accessToken: accessToken.token,
        refreshToken: nextRefreshToken.token,
        accessTokenExpiresAt: accessToken.expiresAt,
        refreshTokenExpiresAt: nextRefreshToken.expiresAt
      }
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

export async function logoutSession(db: Pool, userId: string, workspaceId: string, sessionId: string): Promise<boolean> {
  const result = await db.query(
    `
      UPDATE user_sessions
      SET revoked_at = now()
      WHERE id = $1
        AND user_id = $2
        AND workspace_id = $3
        AND revoked_at IS NULL
    `,
    [sessionId, userId, workspaceId]
  );

  return (result.rowCount ?? 0) > 0;
}

export async function changePassword(
  db: Pool,
  userId: string,
  workspaceId: string,
  currentPassword: string,
  nextPassword: string,
  sessionId: string
): Promise<{ user: UserRecord; accessToken: string; accessTokenExpiresAt: number }> {
  const normalizedNextPassword = normalizePassword(nextPassword);
  const client = await db.connect();

  try {
    await client.query("BEGIN");
    const row = await queryUserWithWorkspaceById(client, userId);
    if (!row || row.workspace_id !== workspaceId) {
      throw new UserServiceError(404, "user_not_found", "User not found");
    }

    const user = toUserRecord(row);
    const workspace = requireWorkspaceRecord(row);
    enforceActiveAccess(user, workspace);

    const validPassword = await bcrypt.compare(currentPassword, row.password_hash);
    if (!validPassword) {
      throw new UserServiceError(401, "invalid_credentials", "Invalid current password");
    }

    const passwordHash = await bcrypt.hash(normalizedNextPassword, PASSWORD_HASH_ROUNDS);
    const updated = await client.query<UserRow>(
      `
        UPDATE users
        SET password_hash = $2,
            force_password_change = false,
            updated_at = now()
        WHERE id = $1
        RETURNING id, email, password_hash, force_password_change, email_verified, preferred_locale, workspace_id, role, status, created_at, updated_at
      `,
      [userId, passwordHash]
    );

    const updatedUser = toUserRecord(updated.rows[0]);
    await client.query(
      `
        UPDATE user_sessions
        SET revoked_at = now()
        WHERE user_id = $1
          AND workspace_id = $2
          AND id <> $3
          AND revoked_at IS NULL
      `,
      [userId, workspaceId, sessionId]
    );
    const token = await mintAccessToken(updatedUser, sessionId);
    await client.query("COMMIT");

    return {
      user: updatedUser,
      accessToken: token.token,
      accessTokenExpiresAt: token.expiresAt
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

export async function verifyEmail(db: Pool, token: string): Promise<UserWithWorkspace> {
  const normalizedToken = token.trim();
  if (!normalizedToken) {
    throw new UserServiceError(400, "invalid_verification_token", "Verification token is required");
  }

  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const userId = await consumeUserToken(client, "email_verification", normalizedToken);
    if (!userId) {
      throw new UserServiceError(404, "verification_not_found", "Verification token not found");
    }

    await clearUserTokens(client, userId, "email_verification");
    const updated = await client.query<UserRow>(
      `
        UPDATE users
        SET email_verified = true,
            updated_at = now()
        WHERE id = $1
        RETURNING id, email, password_hash, force_password_change, email_verified, preferred_locale, workspace_id, role, status, created_at, updated_at
      `,
      [userId]
    );

    const row = updated.rows[0];
    if (!row) {
      throw new UserServiceError(404, "user_not_found", "User not found");
    }

    const workspace = await getWorkspace(client, row.workspace_id);
    if (!workspace) {
      throw new UserServiceError(404, "workspace_not_found", "Workspace not found");
    }

    await client.query("COMMIT");

    return {
      user: toUserRecord(row),
      workspace
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

export async function retriggerEmailVerification(db: Pool, userId: string): Promise<MailDeliveryResult> {
  const client = await db.connect();
  let email: string | null = null;
  let preferredLocale: SupportedLocale = DEFAULT_LOCALE;
  let verificationToken: string | null = null;
  try {
    await client.query("BEGIN");
    const result = await client.query<UserRow>(
      `
        SELECT id, email, email_verified, preferred_locale
        FROM users
        WHERE id = $1
        FOR UPDATE
      `,
      [userId]
    );

    const row = result.rows[0];
    if (!row) {
      throw new UserServiceError(404, "user_not_found", "User not found");
    }

    if (row.email_verified) {
      throw new UserServiceError(400, "already_verified", "Email is already verified");
    }

    email = row.email;
    preferredLocale = normalizePreferredLocale(row.preferred_locale);
    verificationToken = await replaceUserToken(client, userId, "email_verification", EMAIL_VERIFICATION_TOKEN_TTL_SECONDS);

    await client.query("COMMIT");

    if (!email || !verificationToken) {
      throw new UserServiceError(500, "verification_not_issued", "Verification email could not be issued");
    }

    return await sendVerificationEmail(email, verificationToken, preferredLocale);
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

export async function requestPasswordReset(
  db: Pool,
  email: string,
  fallbackLocaleRaw: string | null = null
): Promise<PasswordResetRequestResult> {
  const normalizedEmail = normalizeEmail(email);
  validateEmail(normalizedEmail);
  const client = await db.connect();
  let userEmail: string | null = null;
  let preferredLocale = normalizePreferredLocale(fallbackLocaleRaw);
  let resetToken: string | null = null;

  try {
    await client.query("BEGIN");
    const row = await queryUserWithWorkspaceByEmail(client, normalizedEmail);
    if (!row) {
      await client.query("COMMIT");
      return { requested: false };
    }

    const user = toUserRecord(row);
    const workspace = requireWorkspaceRecord(row);
    if (user.status !== "active" || workspace.status !== "active") {
      await client.query("COMMIT");
      return { requested: false };
    }

    userEmail = row.email;
    preferredLocale = row.preferred_locale ? normalizePreferredLocale(row.preferred_locale) : preferredLocale;
    resetToken = await replaceUserToken(client, row.id, "password_reset", PASSWORD_RESET_TOKEN_TTL_SECONDS);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }

  if (!userEmail || !resetToken) {
    return { requested: false };
  }

  try {
    await sendPasswordResetEmail(userEmail, resetToken, preferredLocale);
  } catch (error) {
    logEmailDeliveryFailure("password reset", userEmail, error);
  }

  return { requested: true };
}

export async function resetPasswordWithToken(db: Pool, token: string, nextPassword: string): Promise<PasswordResetResult> {
  const normalizedToken = token.trim();
  if (!normalizedToken) {
    throw new UserServiceError(400, "invalid_reset_token", "Password reset token is required");
  }

  const normalizedNextPassword = normalizePassword(nextPassword);
  const passwordHash = await bcrypt.hash(normalizedNextPassword, PASSWORD_HASH_ROUNDS);
  const client = await db.connect();

  try {
    await client.query("BEGIN");
    const userId = await consumeUserToken(client, "password_reset", normalizedToken);
    if (!userId) {
      throw new UserServiceError(400, "invalid_reset_token", "Password reset token is invalid or expired");
    }

    const row = await queryUserWithWorkspaceById(client, userId);
    if (!row) {
      throw new UserServiceError(404, "user_not_found", "User not found");
    }

    const user = toUserRecord(row);
    const workspace = requireWorkspaceRecord(row);
    enforceActiveAccess(user, workspace);

    const updated = await client.query<UserRow>(
      `
        UPDATE users
        SET password_hash = $2,
            force_password_change = false,
            updated_at = now()
        WHERE id = $1
        RETURNING id, email, password_hash, force_password_change, email_verified, workspace_id, role, status, created_at, updated_at
      `,
      [userId, passwordHash]
    );

    await clearUserTokens(client, userId, "password_reset");
    await client.query(
      `
        UPDATE user_sessions
        SET revoked_at = now()
        WHERE user_id = $1
          AND revoked_at IS NULL
      `,
      [userId]
    );

    await client.query("COMMIT");

    return {
      user: toUserRecord(updated.rows[0])
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

export async function getUserContext(db: Pool, userId: string): Promise<UserWithWorkspace | null> {
  const client = await db.connect();

  try {
    const row = await queryUserWithWorkspaceById(client, userId);
    if (!row) {
      return null;
    }

    return {
      user: toUserRecord(row),
      workspace: requireWorkspaceRecord(row)
    };
  } finally {
    client.release();
  }
}

export async function listWorkspaceUsers(db: Pool, workspaceId: string): Promise<UserRecord[]> {
  const result = await db.query<UserRow>(
    `
      SELECT id, email, password_hash, force_password_change, email_verified, workspace_id, role, status, created_at, updated_at
      FROM users
      WHERE workspace_id = $1
      ORDER BY created_at DESC, id DESC
    `,
    [workspaceId]
  );

  return result.rows.map(toUserRecord);
}

function normalizeListLimit(limit?: number): number {
  if (limit === undefined) {
    return 20;
  }

  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    throw new UserServiceError(400, "invalid_limit", "limit must be an integer between 1 and 100");
  }

  return limit;
}

function normalizeUserStatusFilter(status?: string): UserStatus | null {
  if (status === undefined) {
    return null;
  }

  if (status !== "active" && status !== "suspended" && status !== "deleted") {
    throw new UserServiceError(400, "invalid_status", "Invalid user status");
  }

  return status;
}

export async function listWorkspaceUsersPage(
  db: Pool,
  workspaceId: string,
  input: ListWorkspaceUsersInput = {}
): Promise<WorkspaceUserListPage> {
  const limit = normalizeListLimit(input.limit);
  const status = normalizeUserStatusFilter(input.status);
  let cursorCreatedAt: Date | null = null;
  let cursorId: string | null = null;

  if (input.cursor) {
    try {
      const decoded = decodePageCursor(input.cursor);
      cursorCreatedAt = decoded.createdAt;
      cursorId = decoded.id;
    } catch {
      throw new UserServiceError(400, "invalid_cursor", "cursor is invalid");
    }
  }

  const values: Array<string | number | Date> = [workspaceId];
  const conditions = ["workspace_id = $1"];

  if (status) {
    values.push(status);
    conditions.push(`status = $${values.length}`);
  }

  if (cursorCreatedAt && cursorId) {
    values.push(cursorCreatedAt, cursorId);
    conditions.push(`(created_at, id) < ($${values.length - 1}, $${values.length})`);
  }

  values.push(limit + 1);
  const result = await db.query<UserRow>(
    `
      SELECT id, email, password_hash, force_password_change, email_verified, workspace_id, role, status, created_at, updated_at
      FROM users
      WHERE ${conditions.join(" AND ")}
      ORDER BY created_at DESC, id DESC
      LIMIT $${values.length}
    `,
    values
  );

  const hasMore = result.rows.length > limit;
  const rows = hasMore ? result.rows.slice(0, limit) : result.rows;
  const lastRow = rows.at(-1);

  return {
    members: rows.map(toUserRecord),
    nextCursor: hasMore && lastRow
      ? encodePageCursor({
          createdAt: lastRow.created_at,
          id: lastRow.id
        })
      : null
  };
}

export async function countActiveWorkspaceUsers(db: Pool, workspaceId: string): Promise<number> {
  const result = await db.query<{ count: string }>(
    `
      SELECT COUNT(*)::text AS count
      FROM users
      WHERE workspace_id = $1
        AND status = 'active'
    `,
    [workspaceId]
  );

  return Number(result.rows[0]?.count ?? "0");
}

export async function getWorkspaceOwnerVerificationState(
  db: Pool,
  workspaceId: string
): Promise<WorkspaceOwnerVerificationState | null> {
  const client = await db.connect();

  try {
    return await queryWorkspaceOwnerVerificationState(client, workspaceId);
  } finally {
    client.release();
  }
}

export async function ensureWorkspaceOwnerVerified(db: Pool, workspaceId: string): Promise<void> {
  const state = await getWorkspaceOwnerVerificationState(db, workspaceId);
  if (!state) {
    throw new UserServiceError(404, "workspace_not_found", "Workspace not found");
  }

  if (!state.ownerUserId) {
    throw new UserServiceError(409, "workspace_owner_missing", "Workspace owner is not configured");
  }

  if (!state.ownerEmailVerified) {
    throw new UserServiceError(
      403,
      "workspace_owner_unverified",
      "Workspace owner email must be verified before performing this action"
    );
  }
}

export async function createWorkspaceMember(
  db: Pool,
  workspaceId: string,
  input: CreateWorkspaceMemberInput
): Promise<UserRecord> {
  const normalizedEmail = normalizeEmail(input.email);
  validateEmail(normalizedEmail);
  if (!isUserRole(input.role)) {
    throw new UserServiceError(400, "invalid_role", "Invalid user role");
  }

  const normalizedPassword = normalizeTemporaryPassword(input.temporaryPassword);
  const passwordHash = await bcrypt.hash(normalizedPassword, PASSWORD_HASH_ROUNDS);
  let verificationToken: string | null = null;

  try {
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      const inserted = await client.query<UserRow>(
        `
          INSERT INTO users (email, password_hash, force_password_change, workspace_id, role, status)
          VALUES ($1, $2, true, $3, $4, 'active')
          RETURNING id, email, password_hash, force_password_change, email_verified, preferred_locale, workspace_id, role, status, created_at, updated_at
        `,
        [normalizedEmail, passwordHash, workspaceId, input.role]
      );
      verificationToken = await replaceUserToken(client, inserted.rows[0].id, "email_verification", EMAIL_VERIFICATION_TOKEN_TTL_SECONDS);
      await client.query("COMMIT");

      if (verificationToken) {
        try {
          await sendVerificationEmail(normalizedEmail, verificationToken, DEFAULT_LOCALE);
        } catch (error) {
          logEmailDeliveryFailure("member verification", normalizedEmail, error);
        }
      }

      return toUserRecord(inserted.rows[0]);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    mapPgError(error);
  }
}

export async function updateWorkspaceMember(
  db: Pool,
  workspaceId: string,
  userId: string,
  updates: UpdateWorkspaceMemberInput
): Promise<UserRecord> {
  if (updates.role !== undefined && !isUserRole(updates.role)) {
    throw new UserServiceError(400, "invalid_role", "Invalid user role");
  }

  if (updates.status !== undefined && updates.status !== "active" && updates.status !== "suspended" && updates.status !== "deleted") {
    throw new UserServiceError(400, "invalid_status", "Invalid user status");
  }

  if (updates.role === undefined && updates.status === undefined) {
    throw new UserServiceError(400, "invalid_update", "At least one field must be provided");
  }

  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const current = await client.query<UserRow>(
      `
        SELECT id, email, password_hash, force_password_change, email_verified, workspace_id, role, status, created_at, updated_at
        FROM users
        WHERE id = $1
          AND workspace_id = $2
        LIMIT 1
        FOR UPDATE
      `,
      [userId, workspaceId]
    );

    const row = current.rows[0];
    if (!row) {
      throw new UserServiceError(404, "user_not_found", "User not found");
    }

    const nextRole = updates.role ?? row.role;
    const nextStatus = updates.status ?? row.status;
    if (row.role === "workspace_admin" && row.status === "active" && (nextRole !== "workspace_admin" || nextStatus !== "active")) {
      const otherAdminIds = await listOtherActiveAdmins(client, workspaceId, row.id);
      if (otherAdminIds.length === 0) {
        throw new UserServiceError(
          409,
          "last_admin_lockout",
          "The last active workspace_admin cannot be demoted, suspended, or deleted"
        );
      }
    }

    const updated = await client.query<UserRow>(
      `
        UPDATE users
        SET role = $3,
            status = $4,
            updated_at = now()
        WHERE id = $1
          AND workspace_id = $2
        RETURNING id, email, password_hash, force_password_change, email_verified, preferred_locale, workspace_id, role, status, created_at, updated_at
      `,
      [userId, workspaceId, nextRole, nextStatus]
    );

    await client.query("COMMIT");
    return toUserRecord(updated.rows[0]);
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

export async function updateUserPreferredLocale(
  db: Pool,
  userId: string,
  workspaceId: string,
  preferredLocaleRaw: string
): Promise<UserRecord> {
  const preferredLocale = normalizePreferredLocale(preferredLocaleRaw);
  const result = await db.query<UserRow>(
    `
      UPDATE users
      SET preferred_locale = $3,
          updated_at = now()
      WHERE id = $1
        AND workspace_id = $2
      RETURNING id, email, password_hash, force_password_change, email_verified, preferred_locale, workspace_id, role, status, created_at, updated_at
    `,
    [userId, workspaceId, preferredLocale]
  );

  const row = result.rows[0];
  if (!row) {
    throw new UserServiceError(404, "user_not_found", "User not found");
  }

  return toUserRecord(row);
}
