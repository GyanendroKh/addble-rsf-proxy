/** @typedef  {import("@ianvs/prettier-plugin-sort-imports").PluginConfig} SortImportsConfig*/
/** @typedef  {import("prettier").Config} PrettierConfig*/

/** @type { PrettierConfig | SortImportsConfig } */
const config = {
  arrowParens: 'avoid',
  printWidth: 80,
  singleQuote: true,
  semi: true,
  trailingComma: 'none',
  tabWidth: 2,

  plugins: ['@ianvs/prettier-plugin-sort-imports'],
  importOrder: [
    '^node:(.*)',
    '^fastify-?(.*)$',
    '^@fastify/(.*)$',
    '<THIRD_PARTY_MODULES>',
    '',
    '^[./]'
  ],
  importOrderParserPlugins: ['typescript', 'decorators-legacy']
};

module.exports = config;
