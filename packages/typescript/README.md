# @varwof/clc

> Preview package. Not for production use and not yet published to npm.
> APIs may change.

TypeScript implementation of the Varwof capability-language semantics.

The intended package name is `@varwof/clc`. From the repository root, build and
pack it with:

```bash
npm ci --prefix ts
npm --prefix packages/typescript test
(cd packages/typescript && npm pack --pack-destination /tmp)
```

```ts
import * as clc from '@varwof/clc';

const decision = clc.authorize(
    { id: 'std/database-v1:query:SELECT', params: { limit: 100 } },
    { id: 'std/database-v1:query:SELECT', params: { limit: 50 } },
);

console.log(clc.CLC_REVISION, decision);
```

The package exposes the core API at the package root. Evidence, scheme
declaration and OCMP helpers are available as `evidence`, `scheme` and `ocmp`
namespaces. Conformance vectors remain in
[`varwof/capability`](https://github.com/varwof/capability).
