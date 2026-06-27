/**
 * turtle-writer.js
 *
 * Helpers that improve the readability of Turtle/TriG output from n3.Writer:
 *
 *   topoWrite(writer, quads)  — feed quads to an N3 Writer using nested [ ]
 *                               notation for blank nodes that appear as an
 *                               object exactly once (tree-edge inlining).
 *
 *   reindent(turtle, step?)   — post-process a Turtle/TriG string so that:
 *                               • top-level predicate continuations use `step`
 *                                 (default 2 spaces) instead of n3.Writer's
 *                                 hard-coded 4;
 *                               • blank-node content at nesting depth d uses
 *                                 step × (d+1), giving a uniform 2-space
 *                                 increment at every level.
 *
 *   expandLiterals(turtle)    — convert STRING_LITERAL2 values that contain
 *                               the \n escape into STRING_LITERAL_LONG2
 *                               ("""…""") with a real embedded newline,
 *                               improving multi-line string readability.
 */

/**
 * Write quads to an N3 Writer using nested [ ] notation for blank nodes that
 * appear as an object exactly once (sole child in a tree edge).  Blank nodes
 * used more than once as objects, or that have no subject triples, fall back
 * to the normal _:label reference.  CONSTRUCT-style duplicate quads are
 * deduplicated before processing.
 *
 * @param {object} writer - n3.Writer instance
 * @param {Iterable} quads - RDFJS quads
 */
function topoWrite(writer, quads) {
  // Deduplicate: CONSTRUCT emits identical triples once per WHERE solution row.
  const termKey = t => t.termType === 'Literal'
    ? `L\0${t.value}\0${t.datatype?.value ?? ''}\0${t.language}`
    : `${t.termType[0]}\0${t.value}`;
  const seen = new Set();
  const deduped = [...quads].filter(q => {
    const k = `${termKey(q.graph)}\0${termKey(q.subject)}\0${q.predicate.value}\0${termKey(q.object)}`;
    return seen.size !== seen.add(k).size;
  });

  // Index quads by (graph, subject); count blank-node object occurrences per graph.
  const bySub  = new Map(); // `${g}\0${termType}\0${val}` → { term, graph, pos: Quad[] }
  const oCount = new Map(); // `${g}\0${bnVal}` → number of times seen as object

  for (const q of deduped) {
    const k = `${q.graph.value}\0${q.subject.termType}\0${q.subject.value}`;
    if (!bySub.has(k)) bySub.set(k, { term: q.subject, graph: q.graph, pos: [] });
    bySub.get(k).pos.push(q);
    if (q.object.termType === 'BlankNode') {
      const ok = `${q.graph.value}\0${q.object.value}`;
      oCount.set(ok, (oCount.get(ok) ?? 0) + 1);
    }
  }

  const inlineable = (bn, graph) =>
    oCount.get(`${graph.value}\0${bn.value}`) === 1 &&
    bySub.has(`${graph.value}\0BlankNode\0${bn.value}`);

  function buildBlank(bn, graph) {
    const entry = bySub.get(`${graph.value}\0BlankNode\0${bn.value}`);
    if (!entry) return writer.blank();
    return writer.blank(entry.pos.map(q => ({
      predicate: q.predicate,
      object: q.object.termType === 'BlankNode' && inlineable(q.object, graph)
        ? buildBlank(q.object, graph)
        : q.object,
    })));
  }

  for (const { term, graph, pos } of bySub.values()) {
    if (term.termType === 'BlankNode' && inlineable(term, graph)) continue;
    for (const q of pos) {
      writer.addQuad(
        q.subject, q.predicate,
        q.object.termType === 'BlankNode' && inlineable(q.object, graph)
          ? buildBlank(q.object, graph)
          : q.object,
        q.graph,
      );
    }
  }
}

/**
 * Post-process an N3.js Writer Turtle/TriG string with uniform 2-space
 * indentation at every level.
 *
 * @param {string} turtle
 * @param {string} [step='  ']
 * @returns {string}
 */
function reindent(turtle, step = '  ') {
  let depth = 0;
  return turtle.split('\n').map(line => {
    const t = line.trimStart();
    if (!t) return '';

    // Leading ] chars close blocks: reduce depth before outputting this line.
    let leading = 0;
    while (leading < t.length && t[leading] === ']') {
      depth = Math.max(0, depth - 1);
      leading++;
    }

    let out;
    if (depth > 0) {
      // Inside a blank-node block: shift by one extra step vs n3.Writer's depth.
      out = step.repeat(depth + 1) + t;
    } else if (leading > 0 || line !== t) {
      // Blank-node closer OR predicate-continuation at depth 0: one step.
      out = step + t;
    } else {
      // Subject line or @prefix: no leading whitespace in n3.Writer output.
      out = line.trimEnd();
    }

    // If line ends with [, count net unbalanced brackets outside string literals.
    if (t.trimEnd().endsWith('[')) {
      let opens = 0, closes = 0, inStr = false, i = 0;
      while (i < t.length) {
        const c = t[i];
        if (c === '\\' && inStr) { i += 2; continue; }
        if (c === '"') { inStr = !inStr; }
        else if (!inStr) {
          if (c === '[') opens++;
          else if (c === ']') closes++;
        }
        i++;
      }
      const netOpen = opens - closes + leading;
      if (netOpen > 0) depth += netOpen;
    }

    return out;
  }).join('\n');
}

/**
 * Replace STRING_LITERAL2 values that contain \n escape with STRING_LITERAL_LONG2.
 *
 * @param {string} turtle
 * @returns {string}
 */
function expandLiterals(turtle) {
  return turtle.replace(/"((?:[^"\\]|\\.)*)"/g, (match, content) => {
    if (!content.includes('\\n')) return match;
    const expanded = content.replace(/\\n/g, '\n');
    if (expanded.includes('"""')) return match;
    return `"""${expanded}"""`;
  });
}

module.exports = { topoWrite, reindent, expandLiterals };
