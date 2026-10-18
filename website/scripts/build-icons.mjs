import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import sharp from 'sharp';

const publicDirectory = fileURLToPath(new URL('../public/', import.meta.url));

export async function buildIcons() {
  const source = await readFile(path.join(publicDirectory, 'favicon.svg'), 'utf8');
  // Raster fallbacks use the original forest color on opaque paper in any theme.
  // Only the browser-rendered SVG follows the browser/OS color preference.
  const light = Buffer.from(source.replace(/<style>[\s\S]*?<\/style>/, ''));
  const render = (size) => sharp(light, { density: 144 })
    .resize(size, size)
    .flatten({ background: '#f7f9f8' })
    .png()
    .toBuffer();

  const sizes = [16, 32, 48];
  const images = await Promise.all(sizes.map(render));
  // ICONDIR + one ICONDIRENTRY per PNG payload (PNG-in-ICO).
  const directory = Buffer.alloc(6 + sizes.length * 16);
  directory.writeUInt16LE(1, 2); // Type: icon, not cursor.
  directory.writeUInt16LE(sizes.length, 4);
  let offset = directory.length;
  for (const [index, size] of sizes.entries()) {
    const entry = 6 + index * 16;
    directory[entry] = size;
    directory[entry + 1] = size;
    directory.writeUInt16LE(1, entry + 4); // Color planes.
    directory.writeUInt16LE(24, entry + 6); // Opaque RGB PNG: 8 bits per channel.
    directory.writeUInt32LE(images[index].length, entry + 8);
    directory.writeUInt32LE(offset, entry + 12);
    offset += images[index].length;
  }
  return {
    'favicon.ico': Buffer.concat([directory, ...images]),
    'apple-touch-icon.png': await render(180),
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  for (const [name, buffer] of Object.entries(await buildIcons())) {
    await writeFile(path.join(publicDirectory, name), buffer);
    console.log(`Generated ${name} (${buffer.length} bytes)`);
  }
}
