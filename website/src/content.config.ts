import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import { readdirSync } from 'node:fs';
import { channel } from './docs-channels.mjs';

const overrides = readdirSync(new URL('./content/docs/_next/', import.meta.url), { recursive: true })
	.filter((file) => /\.(md|mdx)$/.test(String(file))).map(String);
const pattern = ['**/[^_]*.{md,mdx}'];
if (channel === 'next') {
	pattern.push(...overrides.map((file) => `!${file}`));
} else pattern.push('!_next/**');

export const collections = {
	docs: defineCollection({
		loader: glob({
			base: './src/content/docs', pattern,
			generateId: ({ entry, data }) => typeof data.slug === 'string' ? data.slug : entry.replace(/^_next\//, '').replace(/\.(md|mdx)$/, '').replace(/\/index$/, ''),
		}),
		schema: docsSchema(),
	}),
};
