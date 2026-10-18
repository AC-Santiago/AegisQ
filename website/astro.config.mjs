// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { channel, currentChannel, remarkChannelLinks } from './src/docs-channels.mjs';

// https://astro.build/config
export default defineConfig({
	// The packaging step assigns the two splash pages to the apex domain.
	site: 'https://docs.aegisq.dev',
	base: currentChannel.base,
	trailingSlash: 'always',
	outDir: channel === 'next' ? './dist-next' : './dist',
	cacheDir: `./node_modules/.astro-${channel}`,
	markdown: { remarkPlugins: [remarkChannelLinks] },
	integrations: [
		starlight({
			title: 'AegisQ',
			disable404Route: true,
			favicon: '/favicon.svg',
			head: [
				{ tag: 'link', attrs: { rel: 'icon', href: `${currentChannel.base}favicon.ico`, sizes: '16x16 32x32 48x48' } },
				{ tag: 'link', attrs: { rel: 'apple-touch-icon', href: `${currentChannel.base}apple-touch-icon.png`, sizes: '180x180' } },
				{ tag: 'meta', attrs: { name: 'theme-color', content: '#365d51' } },
				...(channel === 'next' ? [{ tag: /** @type {'meta'} */ ('meta'), attrs: { name: 'robots', content: 'noindex, follow' } }] : []),
			],
			customCss: ['./src/styles/docs.css'],
			components: {
				Header: './src/components/DocsHeader.astro',
				Hero: './src/components/LandingHero.astro',
				SiteTitle: './src/components/DocsTitle.astro',
				MobileMenuToggle: './src/components/AccessibleMenu.astro',
				PageTitle: './src/components/VersionedPageTitle.astro',
			},
			expressiveCode: {
				styleOverrides: { borderRadius: '0.375rem' },
			},
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
					label: 'Overview',
					translations: { es: 'Descripción general' },
					slug: '',
				},
				{
					label: 'Getting Started',
					translations: { es: 'Primeros pasos' },
					items: [
						{ slug: 'getting-started/installation' },
						{ slug: 'getting-started/quickstart' },
					],
				},
				{
					label: 'API Reference',
					translations: { es: 'Referencia de API' },
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
					translations: { es: 'Fundamentos internos' },
					items: [
						{ slug: 'internals/architecture' },
						{ slug: 'internals/hybrid-kem-dem' },
						{ slug: 'internals/mathematical-foundation' },
						{ slug: 'internals/security-model' },
					],
				},
				{
					label: 'Reference',
					translations: { es: 'Referencia' },
					items: [
						{ slug: 'reference/fips203-compliance' },
						{ slug: 'reference/glossary' },
					],
				},
			],
		}),
	],
});
