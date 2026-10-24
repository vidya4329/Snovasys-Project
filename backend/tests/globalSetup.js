// Creates a fresh, empty SQLite test database before the suite runs.
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

module.exports = async () => {
  const root = path.resolve(__dirname, '..');
  for (const f of ['test.db', 'test.db-journal']) fs.rmSync(path.join(root, 'prisma', f), { force: true });
  fs.rmSync(path.join(root, 'storage', 'test-uploads'), { recursive: true, force: true });
  execSync('npx prisma db push --skip-generate', {
    cwd: root,
    stdio: 'pipe',
    env: { ...process.env, DATABASE_URL: 'file:./test.db' },
  });
};
