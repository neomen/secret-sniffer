# Building the distributable bundles

The `dist/` directory is generated and intentionally not maintained by hand.

1. Install development dependencies: `npm install`
2. Run tests: `npm test`
3. Generate bundles: `npm run build`

The build creates `secret-sniffer.mjs`, `secret-sniffer.min.mjs`, and `secret-sniffer.cjs` plus source maps. The npm `prepublishOnly` lifecycle runs tests and builds before publication.
