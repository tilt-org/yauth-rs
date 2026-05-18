/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_YAUTH_BASE?: string;
  readonly VITE_ORG_SLUG?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
