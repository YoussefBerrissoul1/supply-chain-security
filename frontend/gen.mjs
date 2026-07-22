import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const codes = [400, 401, 403, 404, 408, 409, 410, 422, 429, 500, 502, 503, 504];
const dir = path.join(__dirname, 'src', 'pages', 'status');

if (!fs.existsSync(dir)) {
  fs.mkdirSync(dir, { recursive: true });
}

codes.forEach(code => {
  const content = `import { StatusLayout } from '@/components/error/StatusLayout';

export default function Page${code}() {
  return <StatusLayout code={${code}} />;
}
`;
  fs.writeFileSync(path.join(dir, `Page${code}.tsx`), content);
});

const unknownContent = `import { StatusLayout } from '@/components/error/StatusLayout';

export default function PageUnknown() {
  return <StatusLayout code="UNKNOWN" />;
}
`;
fs.writeFileSync(path.join(dir, `PageUnknown.tsx`), unknownContent);

console.log('Pages generated!');
