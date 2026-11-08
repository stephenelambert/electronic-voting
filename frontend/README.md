# Frontend

The browser client for the electronic voting system. See the [main README](../README.md) for running the API it talks to.

Run `npm install` first to install its dependencies.

- `npm run dev` runs the development server, which passes `/api` requests to the API on `localhost:5172`.
- `npm test` runs the unit tests.
- `npm run lint` runs ESLint.
- `npx tsc --noEmit -p .` type-checks the app. It leaves out the tests, which run in Node, since Node's types would change how the app's code is checked.
- `npm run build` builds the app into `dist`.
