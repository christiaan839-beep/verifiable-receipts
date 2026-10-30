/**
 * Point arithmetic on edwards25519 (RFC 8032), for the strict Ed25519
 * checks of VAOS 2.0 section 7.3.
 *
 * BigInt, written for correctness, not speed or constant time: every
 * input it sees (a public key, a signature's R) is public. The Python
 * (`edwards25519.py`) and Go (`edwards25519.go`) verifiers, and the
 * conformance verifier `conformance/verify-v2.mjs`, carry the same code
 * with the same constants.
 *
 * Points are in extended coordinates (X, Y, Z, T), with x = X/Z,
 * y = Y/Z and x*y = T/Z, and are added with the formulas of RFC 8032
 * section 5.1.4, which are complete on this curve: they also double,
 * and they take the identity and points of small order.
 */

/** The field prime 2^255 - 19. */
export const P = 2n ** 255n - 19n;
/** The order of the base point. */
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;

const mod = (a: bigint): bigint => {
  const r = a % P;
  return r < 0n ? r + P : r;
};

function pow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  for (let e = exp; e > 0n; e >>= 1n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
  }
  return result;
}

const inv = (a: bigint): bigint => pow(a, P - 2n);

/** The curve constant d = -121665/121666. */
export const D = mod(-121665n * inv(121666n));
/** A square root of -1 mod p. */
export const SQRT_M1 = pow(2n, (P - 1n) / 4n);

/** Why an encoding is refused; the verifiers prefix "public key is " or "signature R is ". */
export const NOT_CANONICAL = "not a canonical encoding";
export const NOT_ON_CURVE = "not a point on the curve";
export const SMALL_ORDER = "a small-order point";
export const NOT_IN_SUBGROUP = "not in the prime-order subgroup";

/** A point in extended coordinates. */
export interface Point {
  X: bigint;
  Y: bigint;
  Z: bigint;
  T: bigint;
}

/** The identity (0, 1), frozen: scalarMult(0n, p) returns this object. */
export const IDENTITY: Readonly<Point> = Object.freeze({ X: 0n, Y: 1n, Z: 1n, T: 0n });

/** p + q (RFC 8032 section 5.1.4); also p + p. */
export function pointAdd(p: Point, q: Point): Point {
  const a = mod((p.Y - p.X) * (q.Y - q.X));
  const b = mod((p.Y + p.X) * (q.Y + q.X));
  const c = mod(2n * p.T * q.T * D);
  const d = mod(2n * p.Z * q.Z);
  const e = b - a;
  const f = d - c;
  const g = d + c;
  const h = b + a;
  return { X: mod(e * f), Y: mod(g * h), Z: mod(f * g), T: mod(e * h) };
}

/** [k]p for k >= 0, by double-and-add from the top bit. */
export function scalarMult(k: bigint, p: Point): Point {
  let q = IDENTITY;
  const bits = k > 0n ? k.toString(2) : "";
  for (const bit of bits) {
    q = pointAdd(q, q);
    if (bit === "1") q = pointAdd(q, p);
  }
  return q;
}

/** Whether p is the identity (0, 1). */
export function isIdentity(p: Point): boolean {
  return mod(p.X) === 0n && mod(p.Y - p.Z) === 0n;
}

/** Whether p and q are the same point. */
export function pointsEqual(p: Point, q: Point): boolean {
  return mod(p.X * q.Z - q.X * p.Z) === 0n && mod(p.Y * q.Z - q.Y * p.Z) === 0n;
}

/** Whether p satisfies -x^2 + y^2 = 1 + d x^2 y^2, with x*y = T/Z. */
export function isOnCurve(p: Point): boolean {
  const x2 = mod(p.X * p.X);
  const y2 = mod(p.Y * p.Y);
  const z2 = mod(p.Z * p.Z);
  return mod(y2 - x2 - z2 - D * p.T * p.T) === 0n && mod(p.X * p.Y - p.Z * p.T) === 0n;
}

/** x^2 = (y^2 - 1) / (d y^2 + 1) for a point with this y. */
const xSquared = (y: bigint): bigint => mod((y * y - 1n) * inv(D * y * y + 1n));

/**
 * The x of the point with this y and sign, given x2 = xSquared(y) (RFC
 * 8032 section 5.1.3), or null.
 */
function recoverX(x2: bigint, sign: bigint): bigint | null {
  if (x2 === 0n) return sign ? null : 0n;
  let x = pow(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * SQRT_M1);
  if (mod(x * x - x2) !== 0n) return null;
  return (x & 1n) !== sign ? P - x : x;
}

/** 4/5, the y of the base point. */
export const BASE_Y = mod(4n * inv(5n));
const BASE_X = recoverX(xSquared(BASE_Y), 0n) as bigint;
/** The base point B. */
export const BASE: Point = { X: BASE_X, Y: BASE_Y, Z: 1n, T: mod(BASE_X * BASE_Y) };

function littleEndian(data: Uint8Array): bigint {
  let n = 0n;
  for (let i = data.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(data[i]);
  return n;
}

/**
 * Decode a 32-byte encoding (RFC 8032 section 5.1.3): [point, null], or
 * [null, NOT_CANONICAL] for a y of p or more, x = 0 with the sign bit
 * set or a length other than 32, or [null, NOT_ON_CURVE] for a y with
 * no x on the curve.
 */
export function decode(data: Uint8Array): [Point, null] | [null, string] {
  if (data.length !== 32) return [null, NOT_CANONICAL];
  const n = littleEndian(data);
  const y = n & ((1n << 255n) - 1n);
  const sign = n >> 255n;
  if (y >= P) return [null, NOT_CANONICAL];
  const x2 = xSquared(y);
  if (x2 === 0n && sign) return [null, NOT_CANONICAL];
  const x = recoverX(x2, sign);
  if (x === null) return [null, NOT_ON_CURVE];
  return [{ X: x, Y: y, Z: 1n, T: mod(x * y) }, null];
}

/** The canonical 32-byte encoding of p (RFC 8032 section 5.1.2). */
export function encode(p: Point): Uint8Array {
  const zi = inv(p.Z);
  const x = mod(p.X * zi);
  let n = mod(p.Y * zi) | ((x & 1n) << 255n);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

/** Whether [8]p is the identity: p is one of the 8 points of small order. */
export function hasSmallOrder(p: Point): boolean {
  return isIdentity(scalarMult(8n, p));
}

/** Whether [L]p is the identity: p has no small-order component. */
export function inPrimeOrderSubgroup(p: Point): boolean {
  return isIdentity(scalarMult(L, p));
}

/**
 * Why an encoding is not a point of order L, or null. In order:
 * NOT_CANONICAL, NOT_ON_CURVE, SMALL_ORDER (the identity included),
 * NOT_IN_SUBGROUP (a mixed-order point).
 */
export function pointProblem(data: Uint8Array): string | null {
  const [p, problem] = decode(data);
  if (p === null) return problem;
  if (hasSmallOrder(p)) return SMALL_ORDER;
  if (!inPrimeOrderSubgroup(p)) return NOT_IN_SUBGROUP;
  return null;
}
