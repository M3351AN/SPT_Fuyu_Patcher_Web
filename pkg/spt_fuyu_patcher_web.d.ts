/* tslint:disable */
/* eslint-disable */

export class PatchResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly already_patched: boolean;
    readonly error_code: string;
    readonly output_filename: string;
    readonly patched_data: any;
    readonly success: boolean;
}

export function patch_file(data: Uint8Array, filename: string, on_progress: Function): Promise<PatchResult>;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_patchresult_free: (a: number, b: number) => void;
    readonly patch_file: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly patchresult_already_patched: (a: number) => number;
    readonly patchresult_error_code: (a: number, b: number) => void;
    readonly patchresult_output_filename: (a: number, b: number) => void;
    readonly patchresult_patched_data: (a: number) => number;
    readonly patchresult_success: (a: number) => number;
    readonly __wasm_bindgen_func_elem_254: (a: number, b: number, c: number, d: number) => void;
    readonly __wasm_bindgen_func_elem_256: (a: number, b: number, c: number, d: number) => void;
    readonly __wbindgen_export: (a: number) => void;
    readonly __wbindgen_export2: (a: number, b: number) => void;
    readonly __wbindgen_export3: (a: number, b: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export5: (a: number, b: number, c: number) => void;
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
