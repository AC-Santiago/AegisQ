// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	integrations: [
		starlight({
			title: 'AegisQ Docs',
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/AC-Santiago/AegisQ',
				},
			],
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'Installation', slug: 'getting-started/installation' },
						{ label: 'Quick Start', slug: 'getting-started/quickstart' },
					],
				},
				{
					label: 'API Reference',
					items: [
						{ label: 'AegisCipher', slug: 'api-reference/aegiscipher' },
						{ label: 'MlKem', slug: 'api-reference/mlkem' },
						{ label: 'Security Levels', slug: 'api-reference/security-levels' },
						{ label: 'Exceptions', slug: 'api-reference/exceptions' },
					],
				},
				{
					label: 'Internals',
					items: [
						{ label: 'Architecture', slug: 'internals/architecture' },
						{ label: 'Mathematical Foundation', slug: 'internals/mathematical-foundation' },
						{ label: 'Security Model', slug: 'internals/security-model' },
						{ label: 'Hybrid KEM-DEM', slug: 'internals/hybrid-kem-dem' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'FIPS 203 Compliance', slug: 'reference/fips203-compliance' },
						{ label: 'Glossary', slug: 'reference/glossary' },
					],
				},
			],
		}),
	],
});
