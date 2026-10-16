// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { entryScript, newBuildAvailable, runningBuild } from './build';

const page = (script: string) => `<!doctype html><html><head>
  <link rel="manifest" href="/manifest.json" />
  <script type="module" crossorigin src="${script}"></script>
  <link rel="stylesheet" crossorigin href="/assets/index-AAA.css">
</head><body><div id="root"></div></body></html>`;

const serve = (body: string, ok = true) =>
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok, text: async () => body })));

afterEach(() => { vi.unstubAllGlobals(); document.head.innerHTML = ''; });

describe('entryScript', () => {
  it('reads the built entry script, as Vite writes it', () => {
    expect(entryScript(page('/assets/index-FzEpKruD.js'))).toBe('/assets/index-FzEpKruD.js');
  });
  it('ignores the dev server entry and pages without one', () => {
    expect(entryScript('<script type="module" src="/src/main.tsx"></script>')).toBeNull();
    expect(entryScript('<p>LightHouse is starting</p>')).toBeNull();
  });
});

describe('runningBuild', () => {
  it('is the entry script of the page this window loaded', () => {
    document.head.innerHTML = '<script type="module" crossorigin src="/assets/index-OLD1.js"></script>';
    expect(runningBuild()).toBe('/assets/index-OLD1.js');
  });
  it('is null under the dev server', () => {
    document.head.innerHTML = '<script type="module" src="/src/main.tsx"></script>';
    expect(runningBuild()).toBeNull();
  });
});

describe('newBuildAvailable', () => {
  it('is true only when the server serves a different build', async () => {
    serve(page('/assets/index-NEW2.js'));
    expect(await newBuildAvailable('/assets/index-OLD1.js')).toBe(true);
    serve(page('/assets/index-OLD1.js'));
    expect(await newBuildAvailable('/assets/index-OLD1.js')).toBe(false);
  });
  it('asks past every cache', async () => {
    serve(page('/assets/index-OLD1.js'));
    await newBuildAvailable('/assets/index-OLD1.js');
    expect(vi.mocked(fetch)).toHaveBeenCalledWith('/', expect.objectContaining({ cache: 'no-store' }));
  });
  it('never reloads on doubt: server down, an error page, no running build', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
    expect(await newBuildAvailable('/assets/index-OLD1.js')).toBe(false);
    serve('Service Unavailable', false);
    expect(await newBuildAvailable('/assets/index-OLD1.js')).toBe(false);
    serve('<p>no script here</p>');
    expect(await newBuildAvailable('/assets/index-OLD1.js')).toBe(false);
    serve(page('/assets/index-NEW2.js'));
    expect(await newBuildAvailable(null)).toBe(false);
  });
});
