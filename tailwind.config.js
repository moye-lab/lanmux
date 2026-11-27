/** Tailwind CSS v3 build config (audit L-41).
 *
 * The panel used to ship the Tailwind Play CDN (browser-side JIT compile,
 * development-only per upstream docs). It is now compiled once, at build
 * time, into frontend/vendor/tailwind.css. Rebuild after any change to
 * frontend/index.html classes or to this file:
 *
 *   npx --yes tailwindcss@3.4.17 -c tailwind.config.js \
 *     -i tailwind.input.css -o frontend/vendor/tailwind.css --minify
 *
 * The theme extension below mirrors the `tailwind.config` that used to be
 * set inline in frontend/index.html for the Play CDN (font stacks only);
 * keep the two in sync if the stacks ever change. Do NOT re-add a Play
 * CDN script tag — vendor files are served same-origin (see
 * frontend/vendor/README.md).
 */
module.exports = {
  content: ['./frontend/index.html'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', '"PingFang SC"', '"Microsoft YaHei"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
};
