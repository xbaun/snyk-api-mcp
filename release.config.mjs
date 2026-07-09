export default {
  branches: ['main'],
  plugins: [
    '@semantic-release/commit-analyzer',
    '@semantic-release/release-notes-generator',
    [
      '@semantic-release/npm',
      {
        npmPublish: true,
      },
    ],
    [
      '@semantic-release/github',
      {
        assets: [
          {
            path: 'build/snyk-api-mcp-layout.tar.gz',
            label: 'Target project layout archive',
          },
        ],
      },
    ],
  ],
};
