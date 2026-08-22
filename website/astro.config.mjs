// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	// Set a site URL so integrations like @astrojs/sitemap can be enabled later.
	// Update this when AegisQ ships a public docs site (e.g. https://aegisq.dev).
	site: 'https://aegisq-pqc.readthedocs.io',
	integrations: [
		starlight({
			title: 'AegisQ Docs',
			description:
				'Post-Quantum Cryptography for Python — ML-KEM (FIPS 203) + AES-256-GCM',
			// i18n: English is the root locale (URLs without /en/ prefix).
			// Spanish translations live under src/content/docs/es/ and use /es/ URLs.
			// Starlight auto-generates the language switcher in the header.
			locales: {
				root: {
					label: 'English',
					lang: 'en',
				},
				es: {
					label: 'Español',
					lang: 'es',
				},
			},
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/AC-Santiago/AegisQ',
				},
				{
					icon: 'seti:python',
					label: 'PyPI',
					href: 'https://pypi.org/project/aegisq-pqc/',
				},
			],
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ slug: 'getting-started/installation' },
						{ slug: 'getting-started/quickstart' },
					],
				},
				{
					label: 'API Reference',
					items: [
						{ slug: 'api-reference/aegiscipher' },
						{ slug: 'api-reference/keypair' },
						{ slug: 'api-reference/mlkem' },
						{ slug: 'api-reference/security-levels' },
						{ slug: 'api-reference/streaming' },
						{ slug: 'api-reference/async-methods' },
						{ slug: 'api-reference/context-manager' },
						{ slug: 'api-reference/ephemeral-session' },
						{ slug: 'api-reference/key-serialization' },
						{ slug: 'api-reference/exceptions' },
					],
				},
				{
					label: 'Internals',
					items: [
						{ slug: 'internals/architecture' },
						{ slug: 'internals/hybrid-kem-dem' },
						{ slug: 'internals/mathematical-foundation' },
						{ slug: 'internals/security-model' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ slug: 'reference/fips203-compliance' },
						{ slug: 'reference/glossary' },
					],
				},
			],
		}),
	],
});
