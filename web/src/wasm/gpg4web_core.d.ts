/* tslint:disable */
/* eslint-disable */

export function decrypt(ciphertext: string, secret_armored: string, passphrase: string, verify_with: any): any;

/**
 * Encrypt text to one or more recipients, optionally signing.
 *
 * `recipients` is an array of armored public keys. `sign_secret` /
 * `sign_passphrase` are optional; pass `undefined`/`null` to skip signing.
 */
export function encrypt(plaintext: string, recipients: any, sign_secret: string | null | undefined, sign_passphrase: string | null | undefined, armor: boolean): string;

export function extract_public_key(secret_armored: string): string;

export function generate_key(options: any): any;

export function inspect_key(armored: string): any;

export function sign_cleartext(text: string, secret_armored: string, passphrase: string): string;

export function sign_detached(data: string, secret_armored: string, passphrase: string): string;

export function start(): void;

export function vault_create(password: string): any;

export function vault_decrypt(identity: any, password: string, envelope: any): string;

export function vault_encrypt(identity: any, plaintext: string): any;

export function vault_verify_password(identity: any, password: string): boolean;

export function verify_cleartext(armored: string, public_armored: string): any;

export function verify_detached(data: string, signature_armored: string, public_armored: string): boolean;

/**
 * Library + crypto backend version string, surfaced in the UI's About page.
 */
export function version(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly decrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: any) => [number, number, number];
    readonly encrypt: (a: number, b: number, c: any, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly extract_public_key: (a: number, b: number) => [number, number, number, number];
    readonly generate_key: (a: any) => [number, number, number];
    readonly inspect_key: (a: number, b: number) => [number, number, number];
    readonly sign_cleartext: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly sign_detached: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly start: () => void;
    readonly vault_create: (a: number, b: number) => [number, number, number];
    readonly vault_decrypt: (a: any, b: number, c: number, d: any) => [number, number, number, number];
    readonly vault_encrypt: (a: any, b: number, c: number) => [number, number, number];
    readonly vault_verify_password: (a: any, b: number, c: number) => [number, number, number];
    readonly verify_cleartext: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly verify_detached: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly version: () => [number, number];
    readonly "LIBBZ2_RS_SYS_v0.1.x_BZ2_bzDecompress": (a: number) => number;
    readonly "LIBBZ2_RS_SYS_v0.1.x_BZ2_bzDecompressInit": (a: number, b: number, c: number) => number;
    readonly "LIBBZ2_RS_SYS_v0.1.x_BZ2_bzCompressInit": (a: number, b: number, c: number, d: number) => number;
    readonly "LIBBZ2_RS_SYS_v0.1.x_BZ2_bzCompress": (a: number, b: number) => number;
    readonly "LIBBZ2_RS_SYS_v0.1.x_BZ2_bzCompressEnd": (a: number) => number;
    readonly "LIBBZ2_RS_SYS_v0.1.x_BZ2_bzDecompressEnd": (a: number) => number;
    readonly "LIBBZ2_RS_SYS_v0.1.x_BZ2_bzBuffToBuffCompress": (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => number;
    readonly "LIBBZ2_RS_SYS_v0.1.x_BZ2_bzBuffToBuffDecompress": (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
