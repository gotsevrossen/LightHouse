/* Notices that the server now serves a different dashboard than the one this window
   is running, e.g. after an update (from "Update now", or the installer run by hand
   while the window stayed open). Vite names the entry script by a hash of its
   content, so the script path in the page is the build's identity. */
const ENTRY = /<script\b[^>]*\btype="module"[^>]*\bsrc="(\/assets\/[^"]+\.js)"/;

export function entryScript(html: string): string | null {
  const match = ENTRY.exec(html);
  return match ? match[1] : null;
}

export function runningBuild(doc: Document = document): string | null {
  return doc.querySelector<HTMLScriptElement>('script[type="module"][src^="/assets/"]')?.getAttribute('src') ?? null;
}

/* True only when both builds are known and differ. Anything else (the server down
   mid-update, the Vite dev server, which has no built entry) means "not now",
   never a reload. */
export async function newBuildAvailable(running: string | null = runningBuild()): Promise<boolean> {
  if (!running) return false;
  try {
    const response = await fetch('/', { cache: 'no-store', credentials: 'same-origin' });
    if (!response.ok) return false;
    const latest = entryScript(await response.text());
    return latest !== null && latest !== running;
  } catch {
    return false;
  }
}
