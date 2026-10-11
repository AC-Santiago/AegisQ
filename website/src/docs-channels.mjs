export const channels = {
  stable: { version: '1.5.0', base: '/', ref: 'v1.5.0' },
  next: { version: '1.6.0-rc1', base: '/next/', ref: 'develop' },
};
export const channel = process.env.AEGISQ_DOCS_CHANNEL || 'stable';
if (!Object.hasOwn(channels, channel)) throw new Error(`Unknown documentation channel: ${channel}`);
export const currentChannel = channels[channel];

export function documentationPath(pathname, target) {
  const path = pathname.replace(/^\/next(?=\/|$)/, '') || '/';
  return channels[target].base.replace(/\/$/, '') + path;
}

export function remarkChannelLinks() {
  return (tree) => {
    const visit = (node) => {
      if (channel === 'next' && ['link', 'definition'].includes(node.type) && /^\/(es\/)?(getting-started|api-reference|internals|reference)\//.test(node.url)) {
        node.url = `/next${node.url}`;
      }
      node.children?.forEach(visit);
    };
    visit(tree);
  };
}
