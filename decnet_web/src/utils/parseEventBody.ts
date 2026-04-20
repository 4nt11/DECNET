// Some producers (notably the SSH PROMPT_COMMAND hook via rsyslog) emit
// k=v pairs inside the syslog MSG body instead of RFC5424 structured-data.
// When the backend's `fields` is empty we salvage those pairs here so the
// UI renders consistent pills regardless of where the structure was set.
//
// A leading non-"key=" token is returned as `head` (e.g. "CMD"). The final
// key consumes the rest of the line so values like `cmd=ls -lah` stay intact.
export interface ParsedBody {
  head: string | null;
  fields: Record<string, string>;
  tail: string | null;
}

export function parseEventBody(msg: string | null | undefined): ParsedBody {
  const empty: ParsedBody = { head: null, fields: {}, tail: null };
  if (!msg) return empty;
  const body = msg.trim();
  if (!body || body === '-') return empty;

  const keyRe = /([A-Za-z_][A-Za-z0-9_]*)=/g;
  const firstKv = body.search(/(^|\s)[A-Za-z_][A-Za-z0-9_]*=/);
  if (firstKv < 0) return { head: null, fields: {}, tail: body };

  const headEnd = firstKv === 0 ? 0 : firstKv;
  const head = headEnd > 0 ? body.slice(0, headEnd).trim() : null;
  const rest = body.slice(headEnd).replace(/^\s+/, '');

  const pairs: Array<{ key: string; valueStart: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = keyRe.exec(rest)) !== null) {
    pairs.push({ key: m[1], valueStart: m.index + m[0].length });
  }

  const fields: Record<string, string> = {};
  for (let i = 0; i < pairs.length; i++) {
    const { key, valueStart } = pairs[i];
    const end = i + 1 < pairs.length
      ? pairs[i + 1].valueStart - pairs[i + 1].key.length - 1
      : rest.length;
    fields[key] = rest.slice(valueStart, end).trim();
  }

  return { head: head && head !== '-' ? head : null, fields, tail: null };
}
