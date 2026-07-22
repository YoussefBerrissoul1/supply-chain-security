[{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/Page400' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 29,
	"startColumn": 35,
	"endLineNumber": 29,
	"endColumn": 59,
	"origin": "extHost1"
},{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/Page401' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 30,
	"startColumn": 35,
	"endLineNumber": 30,
	"endColumn": 59,
	"origin": "extHost1"
},{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/Page403' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 31,
	"startColumn": 35,
	"endLineNumber": 31,
	"endColumn": 59,
	"origin": "extHost1"
},{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/Page404' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 32,
	"startColumn": 35,
	"endLineNumber": 32,
	"endColumn": 59,
	"origin": "extHost1"
},{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/Page408' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 33,
	"startColumn": 35,
	"endLineNumber": 33,
	"endColumn": 59,
	"origin": "extHost1"
},{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/Page409' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 34,
	"startColumn": 35,
	"endLineNumber": 34,
	"endColumn": 59,
	"origin": "extHost1"
},{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/Page410' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 35,
	"startColumn": 35,
	"endLineNumber": 35,
	"endColumn": 59,
	"origin": "extHost1"
},{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/Page422' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 36,
	"startColumn": 35,
	"endLineNumber": 36,
	"endColumn": 59,
	"origin": "extHost1"
},{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/Page429' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 37,
	"startColumn": 35,
	"endLineNumber": 37,
	"endColumn": 59,
	"origin": "extHost1"
},{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/Page500' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 38,
	"startColumn": 35,
	"endLineNumber": 38,
	"endColumn": 59,
	"origin": "extHost1"
},{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/Page502' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 39,
	"startColumn": 35,
	"endLineNumber": 39,
	"endColumn": 59,
	"origin": "extHost1"
},{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/Page503' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 40,
	"startColumn": 35,
	"endLineNumber": 40,
	"endColumn": 59,
	"origin": "extHost1"
},{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/Page504' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 41,
	"startColumn": 35,
	"endLineNumber": 41,
	"endColumn": 59,
	"origin": "extHost1"
},{
	"resource": "/c:/Users/joseph/Documents/nexora/src/App.tsx",
	"owner": "typescript",
	"code": "2307",
	"severity": 8,
	"message": "Cannot find module './pages/status/PageUnknown' or its corresponding type declarations.",
	"source": "ts",
	"startLineNumber": 42,
	"startColumn": 39,
	"endLineNumber": 42,
	"endColumn": 67,
	"origin": "extHost1"
}]
const fs = require('fs');
const path = require('path');

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

console.log('Generated status pages successfully in workspace.');
